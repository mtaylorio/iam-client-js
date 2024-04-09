import IAM, { Action, Effect, rule } from '../src/index';
import sodium from 'libsodium-wrappers-sumo';


const email = process.env.MTAYLOR_IO_EMAIL;
const secretKeyBase64 = process.env.MTAYLOR_IO_SECRET_KEY;


describe('IAM', () => {
  it('should create a user', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const users = iam.users();
    const principal = await users.createUser();
    expect(principal).toBeDefined();
    users.deleteUser(principal.user.id);
  });

  it('should get a user', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const users = iam.users();
    const principal = await users.createUser();
    const user = await users.getUser(principal.user.id);
    expect(user).toBeDefined();
    users.deleteUser(principal.user.id);
  });

  it('should list users', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const users = iam.users();
    const userList = await users.listUsers();
    expect(userList).toBeDefined();
  });

  it('should create a group', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const groups = iam.groups();
    const group = await groups.createGroup()
    expect(group).toBeDefined();
    groups.deleteGroup(group.id)
  });

  it('should get a group', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const groups = iam.groups();
    const group = await groups.createGroup()
    const fetchedGroup = await groups.getGroup(group.id)
    expect(fetchedGroup).toBeDefined();
    groups.deleteGroup(group.id)
  });

  it('should list groups', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const groups = iam.groups();
    const groupList = await groups.listGroups();
    expect(groupList).toBeDefined();
  });

  it('should create a policy', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const policies = iam.policies();
    const policy = await policies.createPolicy('iam.mtaylor.io', [
      rule(Effect.ALLOW, Action.READ, '*'),
      rule(Effect.ALLOW, Action.WRITE, '*')
    ])
    expect(policy).toBeDefined();
    policies.deletePolicy(policy.id);
  });

  it('should get a policy', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const policies = iam.policies();
    const policy = await policies.createPolicy('iam.mtaylor.io', [
      rule(Effect.ALLOW, Action.READ, '*'),
      rule(Effect.ALLOW, Action.WRITE, '*')
    ])
    const fetched = await policies.getPolicy(policy.id);
    expect(fetched).toBeDefined();
    policies.deletePolicy(policy.id);
  });

  it('should list policies', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const policies = iam.policies();
    const policyList = await policies.listPolicies();
    expect(policyList).toBeDefined();
  });
});
