import { AxiosResponse } from 'axios';
export declare const enum Action {
    READ = "Read",
    WRITE = "Write"
}
export declare const enum Effect {
    ALLOW = "Allow",
    DENY = "Deny"
}
export interface UserIdentityObject {
    id: string;
    email?: string;
}
export interface GroupIdentityObject {
    id: string;
    name?: string;
}
export interface PolicyIdentityObject {
    id: string;
    name?: string;
}
export type GroupIdentity = string | GroupIdentityObject;
export type UserIdentity = string | UserIdentityObject;
export type PolicyIdentity = string | PolicyIdentityObject;
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
export declare function rule(effect: Effect, action: Action, resource: string): Rule;
export declare class Principal {
    readonly user: User;
    readonly publicKey: Uint8Array;
    private privateKey;
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
    listUsers(offset?: number, limit?: number): Promise<UserIdentity[]>;
    attachPolicy(userId: string, policyId: string): Promise<void>;
    detachPolicy(userId: string, policyId: string): Promise<void>;
}
export declare class GroupsClient {
    private iam;
    constructor(iam: IAM);
    createGroup(name?: string | null, users?: string[], policies?: string[]): Promise<Group>;
    deleteGroup(id: string): Promise<void>;
    getGroup(id: string): Promise<Group>;
    listGroups(offset?: number, limit?: number): Promise<GroupIdentity[]>;
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
    listPolicies(offset?: number, limit?: number): Promise<PolicyIdentity[]>;
}
