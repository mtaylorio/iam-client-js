import sodium from 'libsodium-wrappers-sumo';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
const DEFAULT_PROTOCOL = 'https';
const DEFAULT_HOST = 'iam.mtaylor.io';
const DEFAULT_PORT = null;
export const LoginStatusValues = [
    "pending" /* LoginStatus.PENDING */,
    "granted" /* LoginStatus.GRANTED */,
    "denied" /* LoginStatus.DENIED */,
];
export const PolicyActions = ["Read" /* Action.READ */, "Write" /* Action.WRITE */];
export const PolicyEffects = ["Allow" /* Effect.ALLOW */, "Deny" /* Effect.DENY */];
export const SortOrders = ["asc" /* SortOrder.ASC */, "desc" /* SortOrder.DESC */];
export const SortUsersByValues = [
    "id" /* SortUsersBy.SORT_USERS_BY_ID */,
    "name" /* SortUsersBy.SORT_USERS_BY_NAME */,
    "email" /* SortUsersBy.SORT_USERS_BY_EMAIL */,
];
export const SortGroupsByValues = [
    "id" /* SortGroupsBy.SORT_GROUPS_BY_ID */,
    "name" /* SortGroupsBy.SORT_GROUPS_BY_NAME */,
];
export const SortPoliciesByValues = [
    "id" /* SortPoliciesBy.SORT_POLICIES_BY_ID */,
    "name" /* SortPoliciesBy.SORT_POLICIES_BY_NAME */,
];
export function rule(effect, action, resource) {
    return { action, effect, resource };
}
export class Principal {
    user;
    publicKey;
    privateKey;
    publicKeyBase64;
    privateKeyBase64;
    constructor(user, privateKey, publicKey = null) {
        this.user = user;
        this.privateKey = privateKey;
        this.publicKey = publicKey ?
            publicKey : sodium.crypto_sign_ed25519_sk_to_pk(privateKey);
        this.publicKeyBase64 = sodium.to_base64(this.publicKey, sodium.base64_variants.URLSAFE);
        this.privateKeyBase64 = sodium.to_base64(this.privateKey, sodium.base64_variants.URLSAFE);
    }
}
export default class IAM {
    protocol;
    host;
    port;
    userId = null;
    secretKey = null;
    publicKey = null;
    loginId = null;
    sessionId = null;
    sessionToken = null;
    sessionExpires = null;
    sessionAddress = null;
    sessionUserId = null;
    user;
    users;
    logins;
    groups;
    policies;
    sessions;
    publicKeys;
    constructor(protocol = DEFAULT_PROTOCOL, host = DEFAULT_HOST, port = DEFAULT_PORT) {
        this.protocol = protocol.endsWith(':') ? protocol.slice(0, -1) : protocol;
        this.host = host;
        this.port = port;
        this.user = new UserClient(this);
        this.users = new UsersClient(this);
        this.logins = new LoginsClient(this);
        this.groups = new GroupsClient(this);
        this.policies = new PoliciesClient(this);
        this.sessions = new SessionsClient(this);
        this.publicKeys = new PublicKeysClient(this);
    }
    async login(userId, secretKey = null) {
        if (secretKey === null || secretKey === '') {
            return await this.loginRequest(userId);
        }
        else {
            return await this.loginWithSecretKey(userId, secretKey);
        }
    }
    async loginRequest(userId, description = 'default') {
        await sodium.ready;
        if (!this.loginId) {
            this.loginId = uuidv4();
        }
        this.userId = userId;
        if (!this.publicKey) {
            const keypair = sodium.crypto_sign_keypair();
            this.publicKey = keypair.publicKey;
            this.secretKey = keypair.privateKey;
        }
        const id = this.loginId;
        const publicKey = {
            description,
            key: sodium.to_base64(this.publicKey, sodium.base64_variants.URLSAFE),
        };
        const loginRequest = { id, publicKey, user: userId };
        const response = await axios.post(this.url('/login'), loginRequest);
        if (response.data.status === 'granted') {
            this.sessionId = response.data.session.id;
            this.sessionToken = response.data.session.token;
            this.sessionExpires = response.data.session.expiration;
            this.sessionAddress = response.data.session.address;
            this.sessionUserId = response.data.session.user;
        }
    }
    async loginWithSecretKey(userId, secretKey) {
        await sodium.ready;
        const secretKeyBytes = typeof secretKey === 'string' ?
            sodium.from_base64(secretKey, sodium.base64_variants.URLSAFE) : secretKey;
        this.userId = userId;
        this.secretKey = secretKeyBytes;
        this.publicKey = sodium.crypto_sign_ed25519_sk_to_pk(secretKeyBytes);
        const response = await this.request('POST', '/user/sessions');
        this.sessionId = response.data.id;
        this.sessionToken = response.data.token;
        this.sessionExpires = response.data.expiration;
        this.sessionAddress = response.data.address;
        this.sessionUserId = response.data.user;
    }
    async logout() {
        await this.request('DELETE', `/user/sessions/${this.sessionId}`);
        this.userId = null;
        this.secretKey = null;
        this.publicKey = null;
        this.sessionId = null;
        this.sessionToken = null;
        this.sessionExpires = null;
        this.sessionAddress = null;
        this.sessionUserId = null;
    }
    async refresh(userId = null, secretKey = null, sessionId = null, sessionToken = null) {
        this.userId = userId ? userId : this.userId;
        this.secretKey = secretKey ? typeof secretKey === 'string' ?
            sodium.from_base64(secretKey, sodium.base64_variants.URLSAFE) :
            secretKey : this.secretKey;
        this.publicKey = this.secretKey ?
            sodium.crypto_sign_ed25519_sk_to_pk(this.secretKey) : null;
        this.sessionId = sessionId ? sessionId : this.sessionId;
        this.sessionToken = sessionToken ? sessionToken : this.sessionToken;
        if (this.sessionId && this.sessionToken) {
            const refreshUrl = `/user/sessions/${this.sessionId}/refresh`;
            const response = await this.request('POST', refreshUrl);
            this.sessionExpires = response.data.expiration;
            this.sessionAddress = response.data.address;
            this.sessionUserId = response.data.user;
        }
    }
    async request(method, path, query = null, body = null) {
        await sodium.ready;
        const url = this.url(path, query);
        const requestId = uuidv4();
        const publicKey = sodium.to_base64(this.publicKey, sodium.base64_variants.URLSAFE);
        const signature = this.signature(requestId, method, path, query);
        const headers = {
            'Authorization': `Signature ${signature}`,
            'X-MTaylor-IO-User-ID': this.userId,
            'X-MTaylor-IO-Request-ID': requestId,
            'X-MTaylor-IO-Public-Key': publicKey,
        };
        if (this.sessionToken) {
            headers['X-MTaylor-IO-Session-Token'] = this.sessionToken;
        }
        const response = await axios.request({
            method,
            url,
            headers,
            data: body,
        });
        return response;
    }
    signature(requestId, method, path, query = null) {
        return sodium.to_base64(sodium.crypto_sign_detached(requestStringToSign(method, this.host, path, query, requestId, this.sessionToken), this.secretKey), sodium.base64_variants.URLSAFE);
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
    async updateUser(update) {
        const response = await this.iam.request('PUT', '/user', null, update);
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
    async createUser(name = null, email = null, groups = [], policies = []) {
        const keypair = sodium.crypto_sign_keypair();
        const publicKeys = [{
                'description': 'default',
                'key': sodium.to_base64(keypair.publicKey, sodium.base64_variants.URLSAFE),
            }];
        const id = uuidv4();
        const user = { id, name, email, groups, policies, publicKeys };
        const response = await this.iam.request('POST', '/users', null, user);
        return new Principal(response.data, keypair.privateKey, keypair.publicKey);
    }
    async updateUser(id, update) {
        const url = `/users/${id}`;
        const response = await this.iam.request('PUT', url, null, update);
        return response.data;
    }
    async deleteUser(id) {
        await this.iam.request('DELETE', `/users/${id}`);
    }
    async getUser(id) {
        const response = await this.iam.request('GET', `/users/${id}`);
        return response.data;
    }
    async listUsers(search = null, sortBy = null, sortOrder = null, offset = null, limit = null) {
        const params = new URLSearchParams();
        if (search) {
            params.append('search', search);
        }
        if (sortBy) {
            params.append('sort', sortBy);
        }
        if (sortOrder) {
            params.append('order', sortOrder);
        }
        if (offset) {
            params.append('offset', offset.toString());
        }
        if (limit) {
            params.append('limit', limit.toString());
        }
        const queryParams = params.toString();
        const query = queryParams === '' ? null : `?${queryParams}`;
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
export class LoginsClient {
    iam;
    constructor(iam) {
        this.iam = iam;
    }
    async getLogin(id, userId = null) {
        const path = userId ? `/users/${userId}/login-requests/${id}` :
            `/user/login-requests/${id}`;
        const response = await this.iam.request('GET', path);
        return response.data;
    }
    async listLogins(userId = null) {
        const path = userId ? `/users/${userId}/login-requests` : `/user/login-requests`;
        const response = await this.iam.request('GET', path);
        return response.data;
    }
    async denyLogin(id, userId = null) {
        const path = userId ? `/users/${userId}/login-requests/${id}/deny` :
            `/user/login-requests/${id}/deny`;
        const response = await this.iam.request('POST', path);
        return response.data;
    }
    async grantLogin(id, userId = null) {
        const path = userId ? `/users/${userId}/login-requests/${id}/grant` :
            `/user/login-requests/${id}/grant`;
        const response = await this.iam.request('POST', path);
        return response.data;
    }
    async deleteLogin(id, userId = null) {
        const path = userId ? `/users/${userId}/login-requests/${id}` :
            `/user/login-requests/${id}`;
        await this.iam.request('DELETE', path);
    }
}
export class PublicKeysClient {
    iam;
    constructor(iam) {
        this.iam = iam;
    }
    async createPublicKey(description, key, userId = null) {
        const publicKey = { description, key };
        const path = userId ? `/users/${userId}/public-keys` : '/user/public-keys';
        const response = await this.iam.request('POST', path, null, publicKey);
        return response.data;
    }
    async deletePublicKey(id, userId = null) {
        const path = userId ? `/users/${userId}/public-keys/${id}` :
            `/user/public-keys/${id}`;
        const response = await this.iam.request('DELETE', path);
        return response.data;
    }
    async listPublicKeys(userId = null) {
        const path = userId ? `/users/${userId}/public-keys` : '/user/public-keys';
        const response = await this.iam.request('GET', path);
        return response.data;
    }
    async getPublicKey(id, userId = null) {
        const path = userId ? `/users/${userId}/public-keys/${id}` :
            `/user/public-keys/${id}`;
        const response = await this.iam.request('GET', path);
        return response.data;
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
    async listGroups(search = null, sortBy = null, sortOrder = null, offset = null, limit = null) {
        const params = new URLSearchParams();
        if (search) {
            params.append('search', search);
        }
        if (sortBy) {
            params.append('sort', sortBy);
        }
        if (sortOrder) {
            params.append('order', sortOrder);
        }
        if (offset !== null) {
            params.append('offset', offset.toString());
        }
        if (limit !== null) {
            params.append('limit', limit.toString());
        }
        const queryParams = params.toString();
        const query = queryParams === '' ? null : `?${queryParams}`;
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
    async createPolicy(spec) {
        const id = uuidv4();
        const { hostname, statements } = spec;
        const policy = { id, hostname, statements };
        if (spec.name) {
            policy['name'] = spec.name;
        }
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
    async listPolicies(search = null, sortBy = null, sortOrder = null, offset = null, limit = null) {
        const params = new URLSearchParams();
        if (search) {
            params.append('search', search);
        }
        if (sortBy) {
            params.append('sort', sortBy);
        }
        if (sortOrder) {
            params.append('order', sortOrder);
        }
        if (offset !== null) {
            params.append('offset', offset.toString());
        }
        if (limit !== null) {
            params.append('limit', limit.toString());
        }
        const queryParams = params.toString();
        const query = queryParams === '' ? null : `?${queryParams}`;
        const response = await this.iam.request('GET', '/policies', query);
        return response.data;
    }
}
export class SessionsClient {
    iam;
    constructor(iam) {
        this.iam = iam;
    }
    async createSession(userId = null) {
        const path = userId ? `/users/${userId}/sessions` : '/user/sessions';
        const response = await this.iam.request('POST', path);
        return response.data;
    }
    async listSessions(userId = null, offset = 0, limit = 100) {
        const query = `?offset=${offset}&limit=${limit}`;
        const path = userId ? `/users/${userId}/sessions` : '/user/sessions';
        const response = await this.iam.request('GET', path, query);
        return response.data;
    }
    async getSession(id, userId = null) {
        const path = userId ? `/users/${userId}/sessions/${id}` : `/user/sessions/${id}`;
        const response = await this.iam.request('GET', path);
        return response.data;
    }
    async deleteSession(id, userId = null) {
        const path = userId ? `/users/${userId}/sessions/${id}` : `/user/sessions/${id}`;
        await this.iam.request('DELETE', path);
    }
    async refreshSession(id, userId = null) {
        const path = userId ? `/users/${userId}/sessions/${id}/refresh` : `/user/sessions/${id}/refresh`;
        await this.iam.request('POST', path);
    }
}
function requestStringToSign(method, host, path, query, requestId, sessionToken) {
    const s = [
        method,
        host,
        path,
        query ? query : '',
        requestId,
    ];
    if (sessionToken) {
        s.push(sessionToken);
    }
    return sodium.from_string(s.join('\n'));
}
