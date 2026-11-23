/* eslint @typescript-eslint/no-unused-expressions:0 */

import { describe, it } from 'node:test';
import { Buffer } from 'node:buffer';
import { expect as chaiExpect } from 'chai';

import { authenticate, dkimSign } from '../../src/mailauth.js';
import { zoneResolver } from '../helpers/dns-zone.js';
import { dkimTxtRecord, privateKey } from '../helpers/keys.js';
import type { ARCResult, AuthenticateResult, DKIMVerifyResult, SPFResult } from '../../src/types.js';

const AUTHOR_DOMAIN = 'author.example';
const AUTHOR_IP = '192.0.2.10';
const HOPS = [
    { domain: 'hop1.example', ip: '192.0.2.11' },
    { domain: 'hop2.example', ip: '192.0.2.12' },
    { domain: 'hop3.example', ip: '192.0.2.13' },
    { domain: 'hop4.example', ip: '192.0.2.14' },
    { domain: 'hop5.example', ip: '192.0.2.15' }
];

const KEY_RECORD = dkimTxtRecord('public-rsa.pem');
const PRIVATE_KEY = privateKey('private-rsa.pem');

const zoneFor = (hops: typeof HOPS) => {
    const zone: Record<string, any> = {
        [AUTHOR_DOMAIN]: { TXT: [[`v=spf1 ip4:${AUTHOR_IP} -all`]] },
        [`dkim._domainkey.${AUTHOR_DOMAIN}`]: { TXT: [[KEY_RECORD]] }
    };

    for (const hop of hops) {
        zone[hop.domain] = { TXT: [[`v=spf1 ip4:${hop.ip} -all`]] };
        zone[`arc._domainkey.${hop.domain}`] = { TXT: [[KEY_RECORD]] };
    }

    return zone;
};

const message = (number: number, body = `body of message ${number}`) =>
    Buffer.from(
        [
            `From: sender@${AUTHOR_DOMAIN}`,
            'To: recipient@example.net',
            `Subject: ARC integration message ${number}`,
            'Date: Mon, 1 Jan 2024 00:00:00 +0000',
            `Message-ID: <arc-${number}@${AUTHOR_DOMAIN}>`,
            '',
            body,
            ''
        ].join('\r\n')
    );

const signAsAuthor = async (input: Buffer, number: number) => {
    const { signatures, errors } = await dkimSign(input, {
        signatureData: [
            {
                signingDomain: AUTHOR_DOMAIN,
                selector: 'dkim',
                privateKey: PRIVATE_KEY,
                algorithm: 'rsa-sha256'
            }
        ],
        signTime: `2024-01-01T00:00:${String(number).padStart(2, '0')}Z`
    });

    chaiExpect(errors).to.deep.equal([]);
    return Buffer.concat([Buffer.from(signatures), input]);
};

const options = (hop: (typeof HOPS)[number], extra?: Record<string, any>) =>
    Object.assign(
        {
            ip: hop.ip,
            helo: `mx.${hop.domain}`,
            sender: `bounce@${hop.domain}`,
            mta: `mx.${hop.domain}`,
            resolver: zoneResolver(zoneFor(HOPS)),
            disableDmarc: true,
            disableBimi: true
        },
        extra || {}
    );

const seal = (hop: (typeof HOPS)[number], extra?: Record<string, any>) =>
    options(
        hop,
        Object.assign(
            {
                seal: {
                    signingDomain: hop.domain,
                    selector: 'arc',
                    privateKey: PRIVATE_KEY
                }
            },
            extra || {}
        )
    );

const forward = async (input: Buffer, hop: (typeof HOPS)[number], extra?: Record<string, any>) => {
    const result = await authenticate(input, seal(hop, extra));
    chaiExpect(result.arc).to.exist;
    chaiExpect((result.arc as ARCResult).sealErrors).to.be.undefined;
    return {
        result,
        message: Buffer.concat([Buffer.from(result.headers), input])
    };
};

const verify = async (input: Buffer, hop: (typeof HOPS)[number], extra?: Record<string, any>) => authenticate(input, options(hop, extra));

const dkimPasses = (result: AuthenticateResult) => ((result.dkim as DKIMVerifyResult).results || []).some(row => row.status.result === 'pass');

describe('ARC integration over ten messages', () => {
    it('Should keep DKIM and SPF results for message 01 without an ARC chain', async () => {
        const signed = await signAsAuthor(message(1), 1);
        const result = await verify(signed, HOPS[0]);

        chaiExpect(dkimPasses(result)).to.be.true;
        chaiExpect((result.spf as SPFResult).status.result).to.equal('pass');
        chaiExpect((result.arc as ARCResult).status.result).to.equal('none');
        chaiExpect(result.arc).to.have.property('chain', false);
        chaiExpect(result.headers).to.match(/dkim=pass/);
        chaiExpect(result.headers).to.match(/spf=pass/);
        chaiExpect(result.headers).to.not.match(/arc=/);
    });

    it('Should validate a one-set ARC chain for message 02', async () => {
        const signed = await signAsAuthor(message(2), 2);
        const firstHop = await forward(signed, HOPS[0]);
        const result = await verify(firstHop.message, HOPS[1]);

        chaiExpect((result.arc as ARCResult).status.result).to.equal('pass');
        chaiExpect((result.arc as ARCResult).i).to.equal(1);
        chaiExpect((result.arc as ARCResult).chain).to.have.lengthOf(1);
        chaiExpect((result.arc as ARCResult).chain?.[0].i).to.equal(1);
        chaiExpect(dkimPasses(result)).to.be.true;
        chaiExpect((result.spf as SPFResult).status.result).to.equal('pass');
    });

    it('Should validate a two-set ARC chain for message 03', async () => {
        const signed = await signAsAuthor(message(3), 3);
        const firstHop = await forward(signed, HOPS[0]);
        const secondHop = await forward(firstHop.message, HOPS[1]);
        const result = await verify(secondHop.message, HOPS[2]);

        chaiExpect((result.arc as ARCResult).status.result).to.equal('pass');
        chaiExpect((result.arc as ARCResult).i).to.equal(2);
        chaiExpect((result.arc as ARCResult).chain).to.have.lengthOf(2);
        chaiExpect((result.arc as ARCResult).info).to.match(/^arc=pass \(i=2 spf=pass dkim=pass/);
    });

    it('Should validate a five-set ARC chain for message 04', async () => {
        const signed = await signAsAuthor(message(4), 4);
        let forwarded = { message: signed } as { message: Buffer };

        for (let i = 0; i < HOPS.length; i++) {
            forwarded = await forward(forwarded.message, HOPS[i]);
        }

        const result = await verify(forwarded.message, HOPS[0]);
        chaiExpect((result.arc as ARCResult).status.result).to.equal('pass');
        chaiExpect((result.arc as ARCResult).i).to.equal(5);
        chaiExpect((result.arc as ARCResult).chain).to.have.lengthOf(5);
        chaiExpect((result.arc as ARCResult).chain?.map(entry => entry.i)).to.deep.equal([1, 2, 3, 4, 5]);
    });

    it('Should preserve an SPF failure in ARC while DKIM still passes for message 05', async () => {
        const signed = await signAsAuthor(message(5), 5);
        const firstHop = await forward(signed, HOPS[0], { ip: '198.51.100.99' });
        const result = await verify(firstHop.message, HOPS[1]);
        const arc = result.arc as ARCResult;

        chaiExpect(arc.status.result).to.equal('pass');
        chaiExpect(arc.authenticationResults?.spf?.result).to.equal('fail');
        chaiExpect(arc.authenticationResults?.dkim?.[0]?.result).to.equal('pass');
        chaiExpect(arc.info).to.match(/spf=fail/);
        chaiExpect(arc.info).to.match(/dkim=pass/);
        chaiExpect((result.spf as SPFResult).status.result).to.equal('pass');
    });

    it('Should preserve a DKIM failure in ARC while the ARC signature passes for message 06', async () => {
        const signed = await signAsAuthor(message(6), 6);
        const changed = Buffer.from(signed.toString('binary').replace('body of message 6', 'changed before forwarding'));
        const firstHop = await forward(changed, HOPS[0]);
        const result = await verify(firstHop.message, HOPS[1]);
        const arc = result.arc as ARCResult;

        chaiExpect(dkimPasses(result)).to.be.false;
        chaiExpect(arc.status.result).to.equal('pass');
        chaiExpect(arc.authenticationResults?.dkim?.[0]?.result).to.equal('neutral');
        chaiExpect(arc.signature && arc.signature.status.result).to.equal('pass');
    });

    it('Should fail message 07 after its body changes below a valid ARC seal', async () => {
        const signed = await signAsAuthor(message(7), 7);
        const firstHop = await forward(signed, HOPS[0]);
        const changed = Buffer.from(firstHop.message.toString('binary').replace('body of message 7', 'tampered after sealing'));
        const result = await verify(changed, HOPS[1]);

        chaiExpect(dkimPasses(result)).to.be.false;
        chaiExpect((result.arc as ARCResult).status.result).to.equal('fail');
        chaiExpect((result.arc as ARCResult).status.comment).to.equal('i=1 no valid signature');
    });

    it('Should fail message 08 when the ARC-Authentication-Results field is missing', async () => {
        const signed = await signAsAuthor(message(8), 8);
        const firstHop = await forward(signed, HOPS[0]);
        const broken = Buffer.from(firstHop.message.toString('binary').replace(/^ARC-Authentication-Results: i=1;[^\r]*\r\n/m, ''));
        const result = await verify(broken, HOPS[1]);

        chaiExpect((result.arc as ARCResult).status.result).to.equal('fail');
        chaiExpect((result.arc as ARCResult).status.comment).to.equal('i=1 no arc-authentication-results set');
        chaiExpect((result.dkim as DKIMVerifyResult).results).to.exist;
    });

    it('Should leave message 09 unmodified when disableArc is set', async () => {
        const signed = await signAsAuthor(message(9), 9);
        const firstHop = await forward(signed, HOPS[0]);
        const result = await verify(firstHop.message, HOPS[1], { disableArc: true });

        chaiExpect(result.arc).to.equal(false);
        chaiExpect(dkimPasses(result)).to.be.true;
        chaiExpect((result.spf as SPFResult).status.result).to.equal('pass');
        chaiExpect(result.headers).to.match(/dkim=pass/);
        chaiExpect(result.headers).to.match(/spf=pass/);
        chaiExpect(result.headers).to.not.match(/arc=/);
    });

    it('Should validate message 10 in strict mode and report the remote IP', async () => {
        const signed = await signAsAuthor(message(10), 10);
        const firstHop = await forward(signed, HOPS[0]);
        const result = await verify(firstHop.message, HOPS[1], { strict: true });
        const arc = result.arc as ARCResult;

        chaiExpect(arc.status.result).to.equal('pass');
        chaiExpect(arc.info).to.equal(`arc=pass (i=1 spf=pass dkim=pass dkdomain=${AUTHOR_DOMAIN}) smtp.remote-ip=${HOPS[1].ip}`);
        chaiExpect(result.headers).to.match(/^Authentication-Results: /);
        chaiExpect(result.headers.indexOf('Authentication-Results:')).to.be.lessThan(result.headers.indexOf('Received-SPF:'));
    });
});
