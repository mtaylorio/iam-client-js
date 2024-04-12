import { AxiosResponse } from 'axios';
export declare const enum Action {
    READ = "Read",
    WRITE = "Write"
}
export declare const enum Effect {
    ALLOW = "Allow",
    DENY = "Deny"
}
interface UserIdentityObject {
    id: string;
    email?: string;
}
interface GroupIdentityObject {
    id: string;
    name?: string;
}
interface PolicyIdentityObject {
    id: string;
    name?: string;
}
type GroupIdentity = string | GroupIdentityObject;
type UserIdentity = string | UserIdentityObject;
type PolicyIdentity = string | PolicyIdentityObject;
interface Rule {
    action: Action;
    effect: Effect;
    resource: string;
}
interface Policy {
    id: string;
    name: string | undefined;
    hostname: string;
    statements: Rule[];
}
interface User {
    id: string;
    email: string | null;
    groups: GroupIdentity[];
    policies: PolicyIdentity[];
    publicKeys: {
        description: string;
        key: string;
    }[];
}
interface Group {
    id: string;
    name: string | null;
    users: UserIdentity[];
    policies: PolicyIdentity[];
}
export declare function rule(effect: Effect, action: Action, resource: string): Rule;
export declare class Principal {
    readonly user: User;
    readonly publicKey: Uint8Array;
    private privateKey;
    constructor(user: User, privateKey: Uint8Array, publicKey?: Uint8Array | null);
}
export default class IAM {
    private protocol;
    private host;
    private port;
    private userId;
    private secretKey;
    private publicKey;
    private sessionId;
    private sessionToken;
    user: UserClient;
    users: UsersClient;
    groups: GroupsClient;
    policies: PoliciesClient;
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
    listUsers(offset?: number, limit?: number): Promise<User[]>;
    attachPolicy(userId: string, policyId: string): Promise<void>;
    detachPolicy(userId: string, policyId: string): Promise<void>;
}
export declare class GroupsClient {
    private iam;
    constructor(iam: IAM);
    createGroup(name?: string | null, users?: string[], policies?: string[]): Promise<Group>;
    deleteGroup(id: string): Promise<void>;
    getGroup(id: string): Promise<Group>;
    listGroups(offset?: number, limit?: number): Promise<Group[]>;
    attachPolicy(groupId: string, policyId: string): Promise<void>;
    detachPolicy(groupId: string, policyId: string): Promise<void>;
    addMember(groupId: string, userId: string): Promise<void>;
    removeMember(groupId: string, userId: string): Promise<void>;
}
export declare class PoliciesClient {
    private iam;
    constructor(iam: IAM);
    createPolicy(hostname: string, statements: Rule[]): Promise<Policy>;
    deletePolicy(id: string): Promise<void>;
    getPolicy(id: string): Promise<string>;
    listPolicies(offset?: number, limit?: number): Promise<string[]>;
}
export {};
