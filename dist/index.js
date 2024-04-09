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
        const url = this.url(path);
        const requestId = uuidv4();
        const signature = this.signature(requestId, method, path, query);
        const headers = {
            'X-MTaylor-IO-Request-ID': requestId,
            'X-MTaylor-IO-User-ID': this.userId,
            'X-MTaylor-IO-Signature': signature,
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
    url(path) {
        return [
            this.protocol,
            '://',
            this.host,
            this.port ? `:${this.port}` : '',
            path,
        ].join('');
    }
}
function requestStringToSign(method, host, path, query, requestId) {
    return sodium.from_string([
        method,
        host,
        path,
        query,
        requestId,
    ].join('\n'));
}
//# sourceMappingURL=index.js.map