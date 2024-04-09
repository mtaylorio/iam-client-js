import sodium from 'libsodium-wrappers-sumo';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
export class Users {
    iam;
    constructor(iam) {
        this.iam = iam;
    }
    async createUser(email = null, groups = [], policies = []) {
        const keypair = sodium.crypto_sign_keypair();
        const publicKeys = [{
                'description': 'default',
                'key': sodium.to_base64(keypair.publicKey, sodium.base64_variants.ORIGINAL),
            }];
        const id = uuidv4();
        const user = { id, email, groups, policies, publicKeys };
        const response = await this.iam.request('POST', '/users', null, user);
        return {
            keypair,
            user: response.data,
        };
    }
    async deleteUser(id) {
        await this.iam.request('DELETE', `/users/${id}`);
    }
    async getUser(id) {
        const response = await this.iam.request('GET', `/users/${id}`);
        return response.data;
    }
    async listUsers(offset = 0, limit = 100) {
        const query = `?offset=${offset}&limit=${limit}`;
        const response = await this.iam.request('GET', '/users', query);
        return response.data;
    }
}
export default class IAM {
    protocol;
    host;
    port;
    userId;
    secretKey;
    publicKey;
    constructor(userId, secretKey, protocol, host, port) {
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        this.userId = userId;
        this.secretKey = secretKey;
        this.publicKey = sodium.crypto_sign_ed25519_sk_to_pk(secretKey);
    }
    static async client(userId, secretKey, protocol = 'https', host = 'iam.mtaylor.io', port = null) {
        await sodium.ready;
        return new IAM(userId, secretKey, protocol, host, port);
    }
    async request(method, path, query = null, body = null) {
        const url = this.url(path, query);
        const requestId = uuidv4();
        const publicKey = sodium.to_base64(this.publicKey, sodium.base64_variants.ORIGINAL);
        const signature = this.signature(requestId, method, path, query);
        const headers = {
            'Authorization': `Signature ${signature}`,
            'X-MTaylor-IO-User-ID': this.userId,
            'X-MTaylor-IO-Request-ID': requestId,
            'X-MTaylor-IO-Public-Key': publicKey,
        };
        const response = await axios.request({
            method,
            url,
            headers,
            data: body,
        });
        return response;
    }
    signature(requestId, method, path, query = null) {
        return sodium.to_base64(sodium.crypto_sign_detached(requestStringToSign(method, this.host, path, query, requestId), this.secretKey), sodium.base64_variants.ORIGINAL);
    }
    url(path, query = null) {
        return [
            this.protocol,
            '://',
            this.host,
            this.port ? `:${this.port}` : '',
            path,
            query ? query : '',
        ].join('');
    }
}
function requestStringToSign(method, host, path, query, requestId) {
    const s = [
        method,
        host,
        path,
        query ? query : '',
        requestId,
    ].join('\n');
    return sodium.from_string(s);
}
//# sourceMappingURL=index.js.map