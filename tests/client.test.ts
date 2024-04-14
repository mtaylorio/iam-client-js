import IAM, { Action, Effect, rule } from '../src/index';
import sodium from 'libsodium-wrappers-sumo';


const email = process.env.MTAYLOR_IO_EMAIL;
const secretKeyBase64 = process.env.MTAYLOR_IO_SECRET_KEY;
const url = process.env.MTAYLOR_IO_URL || 'https://iam.mtaylor.io';

const iamUrl = new URL(url);

const iam = new IAM(iamUrl.protocol, iamUrl.hostname, parseInt(iamUrl.port));


beforeAll(async () => {
  await iam.login(email, secretKeyBase64);
});


afterAll(async () => {
  await iam.logout();
});


describe('IAM', () => {
  it('should get user', async () => {
    const user = await iam.user.getUser();
    expect(user.email).toBe(email);
  });

  it('should create a user', async () => {
    const users = iam.users;
    const principal = await users.createUser();
    expect(principal).toBeDefined();
    users.deleteUser(principal.user.id);
  });

  it('should get a user', async () => {
    const users = iam.users;
    const principal = await users.createUser();
    const user = await users.getUser(principal.user.id);
    expect(user).toBeDefined();
    users.deleteUser(principal.user.id);
  });

  it('should list users', async () => {
    const users = iam.users;
    const userList = await users.listUsers();
    expect(userList).toBeDefined();
  });

  it('should create a group', async () => {
    const groups = iam.groups;
    const group = await groups.createGroup()
    expect(group).toBeDefined();
    groups.deleteGroup(group.id)
  });

  it('should get a group', async () => {
    const groups = iam.groups;
    const group = await groups.createGroup()
    const fetchedGroup = await groups.getGroup(group.id)
    expect(fetchedGroup).toBeDefined();
    groups.deleteGroup(group.id)
  });

  it('should list groups', async () => {
    const groups = iam.groups;
    const groupList = await groups.listGroups();
    expect(groupList).toBeDefined();
  });

  it('should create a policy', async () => {
    const policies = iam.policies;
    const policy = await policies.createPolicy({
      hostname: 'iam.mtaylor.io',
      statements: [
        rule(Effect.ALLOW, Action.READ, '*'),
        rule(Effect.ALLOW, Action.WRITE, '*')
      ]
    })
    expect(policy).toBeDefined();
    policies.deletePolicy(policy.id);
  });

  it('should get a policy', async () => {
    const policies = iam.policies;
    const policy = await policies.createPolicy({
      hostname: 'iam.mtaylor.io', statements: [
        rule(Effect.ALLOW, Action.READ, '*'),
        rule(Effect.ALLOW, Action.WRITE, '*')
      ]
    })
    const fetched = await policies.getPolicy(policy.id);
    expect(fetched).toBeDefined();
    policies.deletePolicy(policy.id);
  });

  it('should list policies', async () => {
    const policies = iam.policies;
    const policyList = await policies.listPolicies();
    expect(policyList).toBeDefined();
  });

  it('should attach a policy to current user', async () => {
    const policy = await iam.policies.createPolicy({
      hostname: 'iam.mtaylor.io',
      statements: [
        rule(Effect.ALLOW, Action.READ, '*'),
        rule(Effect.ALLOW, Action.WRITE, '*')
      ]
    });
    await iam.user.attachPolicy(policy.id);
    iam.policies.deletePolicy(policy.id);
  });

  it('should detach a policy from current user', async () => {
    const policy = await iam.policies.createPolicy({
      hostname: 'iam.mtaylor.io',
      statements: [
        rule(Effect.ALLOW, Action.READ, '*'),
        rule(Effect.ALLOW, Action.WRITE, '*')
      ]
    });
    await iam.user.attachPolicy(policy.id);
    await iam.user.detachPolicy(policy.id);
    iam.policies.deletePolicy(policy.id);
  });

  it('should attach a policy to a group', async () => {
    const policy = await iam.policies.createPolicy({
      hostname: 'iam.mtaylor.io',
      statements: [
        rule(Effect.ALLOW, Action.READ, '*'),
        rule(Effect.ALLOW, Action.WRITE, '*')
      ]
    });
    const group = await iam.groups.createGroup();
    await iam.groups.attachPolicy(group.id, policy.id);
    iam.policies.deletePolicy(policy.id);
    iam.groups.deleteGroup(group.id);
  });

  it('should detach a policy from a group', async () => {
    const policy = await iam.policies.createPolicy({
      hostname: 'iam.mtaylor.io',
      statements: [
        rule(Effect.ALLOW, Action.READ, '*'),
        rule(Effect.ALLOW, Action.WRITE, '*')
      ]
    });
    const group = await iam.groups.createGroup();
    await iam.groups.attachPolicy(group.id, policy.id);
    await iam.groups.detachPolicy(group.id, policy.id);
    iam.policies.deletePolicy(policy.id);
    iam.groups.deleteGroup(group.id);
  });

  it('should add a user to a group', async () => {
    const group = await iam.groups.createGroup();
    const principal = await iam.users.createUser();
    await iam.groups.addMember(group.id, principal.user.id);
    iam.groups.deleteGroup(group.id);
    iam.users.deleteUser(principal.user.id);
  });

  it('should remove a user from a group', async () => {
    const group = await iam.groups.createGroup();
    const principal = await iam.users.createUser();
    await iam.groups.addMember(group.id, principal.user.id);
    await iam.groups.removeMember(group.id, principal.user.id);
    iam.groups.deleteGroup(group.id);
    iam.users.deleteUser(principal.user.id);
  });
});
