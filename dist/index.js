import sodium from 'libsodium-wrappers-sumo';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
const DEFAULT_PROTOCOL = 'https';
const DEFAULT_HOST = 'iam.mtaylor.io';
const DEFAULT_PORT = null;
export var Action;
(function (Action) {
    Action["READ"] = "Read";
    Action["WRITE"] = "Write";
})(Action || (Action = {}));
export var Effect;
(function (Effect) {
    Effect["ALLOW"] = "Allow";
    Effect["DENY"] = "Deny";
})(Effect || (Effect = {}));
export function rule(effect, action, resource) {
    return { action, effect, resource };
}
export class Principal {
    user;
    publicKey;
    privateKey;
    constructor(user, privateKey, publicKey = null) {
        this.user = user;
        this.privateKey = privateKey;
        this.publicKey = publicKey ?
            publicKey : sodium.crypto_sign_ed25519_sk_to_pk(privateKey);
    }
    async client(protocol = DEFAULT_PROTOCOL, host = DEFAULT_HOST, port = DEFAULT_PORT) {
        return await IAM.client(this.user.id, this.privateKey, protocol, host, port);
    }
}
export default class IAM {
    protocol;
    host;
    port;
    userId;
    secretKey;
    publicKey;
    user;
    users;
    groups;
    policies;
    constructor(userId, secretKey, protocol, host, port) {
        const secretKeyBytes = typeof secretKey === 'string' ?
            sodium.from_base64(secretKey, sodium.base64_variants.ORIGINAL) : secretKey;
        this.protocol = protocol;
        this.host = host;
        this.port = port;
        this.userId = userId;
        this.secretKey = secretKeyBytes;
        this.publicKey = sodium.crypto_sign_ed25519_sk_to_pk(secretKeyBytes);
        this.user = new UserClient(this);
        this.users = new UsersClient(this);
        this.groups = new GroupsClient(this);
        this.policies = new PoliciesClient(this);
    }
    static async client(userId, secretKey, protocol = DEFAULT_PROTOCOL, host = DEFAULT_HOST, port = DEFAULT_PORT) {
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
export class UserClient {
    iam;
    constructor(iam) {
        this.iam = iam;
    }
    async getUser() {
        const response = await this.iam.request('GET', '/user');
        return response.data;
    }
    async deleteUser() {
        await this.iam.request('DELETE', '/user');
    }
    async attachPolicy(policyId) {
        await this.iam.request('POST', `/user/policies/${policyId}`);
    }
    async detachPolicy(policyId) {
        await this.iam.request('DELETE', `/user/policies/${policyId}`);
    }
}
export class UsersClient {
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
        return new Principal(response.data, keypair.privateKey, keypair.publicKey);
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
    async attachPolicy(userId, policyId) {
        await this.iam.request('POST', `/users/${userId}/policies/${policyId}`);
    }
    async detachPolicy(userId, policyId) {
        await this.iam.request('DELETE', `/users/${userId}/policies/${policyId}`);
    }
}
export class GroupsClient {
    iam;
    constructor(iam) {
        this.iam = iam;
    }
    async createGroup(name = null, users = [], policies = []) {
        const id = uuidv4();
        const group = { id, name, users, policies };
        const response = await this.iam.request('POST', '/groups', null, group);
        return response.data;
    }
    async deleteGroup(id) {
        await this.iam.request('DELETE', `/groups/${id}`);
    }
    async getGroup(id) {
        const response = await this.iam.request('GET', `/groups/${id}`);
        return response.data;
    }
    async listGroups(offset = 0, limit = 100) {
        const query = `?offset=${offset}&limit=${limit}`;
        const response = await this.iam.request('GET', '/groups', query);
        return response.data;
    }
    async attachPolicy(groupId, policyId) {
        await this.iam.request('POST', `/groups/${groupId}/policies/${policyId}`);
    }
    async detachPolicy(groupId, policyId) {
        await this.iam.request('DELETE', `/groups/${groupId}/policies/${policyId}`);
    }
    async addMember(groupId, userId) {
        await this.iam.request('POST', `/groups/${groupId}/members/${userId}`);
    }
    async removeMember(groupId, userId) {
        await this.iam.request('DELETE', `/groups/${groupId}/members/${userId}`);
    }
}
export class PoliciesClient {
    iam;
    constructor(iam) {
        this.iam = iam;
    }
    async createPolicy(hostname, statements) {
        const id = uuidv4();
        const policy = { id, hostname, statements };
        const response = await this.iam.request('POST', '/policies', null, policy);
        return response.data;
    }
    async deletePolicy(id) {
        await this.iam.request('DELETE', `/policies/${id}`);
    }
    async getPolicy(id) {
        const response = await this.iam.request('GET', `/policies/${id}`);
        return response.data;
    }
    async listPolicies(offset = 0, limit = 100) {
        const query = `?offset=${offset}&limit=${limit}`;
        const response = await this.iam.request('GET', '/policies', query);
        return response.data;
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