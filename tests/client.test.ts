import IAM, { Users, Groups } from '../src/index';
import sodium from 'libsodium-wrappers-sumo';


const email = process.env.MTAYLOR_IO_EMAIL;
const secretKeyBase64 = process.env.MTAYLOR_IO_SECRET_KEY;


describe('IAM', () => {
  it('should create a user', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const users = new Users(iam);
    const principal = await users.createUser()
    expect(principal).toBeDefined();
    users.deleteUser(principal.user.id)
  });

  it('should get a user', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const users = new Users(iam);
    const principal = await users.createUser()
    const user = await users.getUser(principal.user.id)
    expect(user).toBeDefined();
    users.deleteUser(principal.user.id)
  });

  it('should list users', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const users = new Users(iam);
    const userList = await users.listUsers()
    expect(userList).toBeDefined();
  });

  it('should create a group', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const groups = new Groups(iam);
    const group = await groups.createGroup()
    expect(group).toBeDefined();
    groups.deleteGroup(group.id)
  });

  it('should get a group', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const groups = new Groups(iam);
    const group = await groups.createGroup()
    const fetchedGroup = await groups.getGroup(group.id)
    expect(fetchedGroup).toBeDefined();
    groups.deleteGroup(group.id)
  });

  it('should list groups', async () => {
    const iam = await IAM.client(email, secretKeyBase64);
    const groups = new Groups(iam);
    const groupList = await groups.listGroups()
    expect(groupList).toBeDefined();
  });
});
