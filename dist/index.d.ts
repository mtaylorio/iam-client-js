import { AxiosResponse } from 'axios';
export declare const enum Action {
    READ = "Read",
    WRITE = "Write"
}
export declare const PolicyActions: Action[];
export declare const enum Effect {
    ALLOW = "Allow",
    DENY = "Deny"
}
export declare const PolicyEffects: Effect[];
export interface UserIdentity {
    id: string;
    email?: string;
}
export interface GroupIdentity {
    id: string;
    name?: string;
}
export interface PolicyIdentity {
    id: string;
    name?: string;
}
export interface Rule {
    action: Action;
    effect: Effect;
    resource: string;
}
export interface Policy {
    id: string;
    name: string | undefined;
    hostname: string;
    statements: Rule[];
}
export interface PolicySpec {
    name?: string;
    hostname: string;
    statements: Rule[];
}
export interface User {
    id: string;
    email: string | null;
    groups: GroupIdentity[];
    policies: PolicyIdentity[];
    publicKeys: {
        description: string;
        key: string;
    }[];
}
export interface Group {
    id: string;
    name: string | null;
    users: UserIdentity[];
    policies: PolicyIdentity[];
}
export interface Session {
    id: string;
    user: string;
    address: string;
    expiration: string;
}
export interface CreateSession {
    id: string;
    user: string;
    token: string;
    address: string;
    expiration: string;
}
export interface UsersResponse {
    items: UserIdentity[];
    limit: number;
    offset: number;
    total: number;
}
export interface GroupsResponse {
    items: GroupIdentity[];
    limit: number;
    offset: number;
    total: number;
}
export interface PoliciesResponse {
    items: PolicyIdentity[];
    limit: number;
    offset: number;
    total: number;
}
export interface SessionsResponse {
    items: Session[];
    limit: number;
    offset: number;
    total: number;
}
export declare function rule(effect: Effect, action: Action, resource: string): Rule;
export declare class Principal {
    readonly user: User;
    readonly publicKey: Uint8Array;
    readonly privateKey: Uint8Array;
    readonly publicKeyBase64: string;
    readonly privateKeyBase64: string;
    constructor(user: User, privateKey: Uint8Array, publicKey?: Uint8Array | null);
}
export default class IAM {
    protocol: string;
    host: string;
    port: number | null;
    userId: string | null;
    secretKey: Uint8Array | null;
    publicKey: Uint8Array | null;
    sessionId: string | null;
    sessionToken: string | null;
    sessionExpires: string | null;
    sessionAddress: string | null;
    sessionUserId: string | null;
    user: UserClient;
    users: UsersClient;
    groups: GroupsClient;
    policies: PoliciesClient;
    sessions: SessionsClient;
    constructor(protocol?: string, host?: string, port?: number | null);
    login(userId: string, secretKey: Uint8Array | string): Promise<void>;
    logout(): Promise<void>;
    refresh(userId?: string | null, secretKey?: Uint8Array | string | null, sessionId?: string | null, sessionToken?: string | null): Promise<void>;
    request(method: string, path: string, query?: string | null, body?: any | null): Promise<AxiosResponse>;
    signature(requestId: string, method: string, path: string, query?: string | null): string;
    url(path: string, query?: string | null): string;
}
export declare class UserClient {
    private iam;
    constructor(iam: IAM);
    getUser(): Promise<User>;
    deleteUser(): Promise<void>;
    attachPolicy(policyId: string): Promise<void>;
    detachPolicy(policyId: string): Promise<void>;
}
export declare class UsersClient {
    private iam;
    constructor(iam: IAM);
    createUser(email?: string | null, groups?: string[], policies?: string[]): Promise<Principal>;
    deleteUser(id: string): Promise<void>;
    getUser(id: string): Promise<User>;
    listUsers(search?: string | null, offset?: number, limit?: number): Promise<UsersResponse>;
    attachPolicy(userId: string, policyId: string): Promise<void>;
    detachPolicy(userId: string, policyId: string): Promise<void>;
}
export declare class GroupsClient {
    private iam;
    constructor(iam: IAM);
    createGroup(name?: string | null, users?: string[], policies?: string[]): Promise<Group>;
    deleteGroup(id: string): Promise<void>;
    getGroup(id: string): Promise<Group>;
    listGroups(search?: string | null, offset?: number, limit?: number): Promise<GroupsResponse>;
    attachPolicy(groupId: string, policyId: string): Promise<void>;
    detachPolicy(groupId: string, policyId: string): Promise<void>;
    addMember(groupId: string, userId: string): Promise<void>;
    removeMember(groupId: string, userId: string): Promise<void>;
}
export declare class PoliciesClient {
    private iam;
    constructor(iam: IAM);
    createPolicy(spec: PolicySpec): Promise<Policy>;
    deletePolicy(id: string): Promise<void>;
    getPolicy(id: string): Promise<Policy>;
    listPolicies(search?: string | null, offset?: number, limit?: number): Promise<PoliciesResponse>;
}
export declare class SessionsClient {
    private iam;
    constructor(iam: IAM);
    createSession(userId?: string | null): Promise<CreateSession>;
    listSessions(userId?: string | null, offset?: number, limit?: number): Promise<SessionsResponse>;
    getSession(id: string, userId?: string | null): Promise<Session>;
    deleteSession(id: string, userId?: string | null): Promise<void>;
    refreshSession(id: string, userId?: string | null): Promise<void>;
}
