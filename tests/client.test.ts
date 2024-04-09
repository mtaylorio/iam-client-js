import IAM, { Users } from '../src/index';
import sodium from 'libsodium-wrappers-sumo';


describe('IAM', () => {
  it('should create a new IAM client', async () => {
    await sodium.ready;
    const email = process.env.MTAYLOR_IO_EMAIL;
    const secretKey = sodium.from_base64(
      process.env.MTAYLOR_IO_SECRET_KEY, sodium.base64_variants.ORIGINAL);

    const iam = await IAM.client(email, secretKey);

    expect(iam).toBeInstanceOf(IAM);
  });

  it('should create a signature', async () => {
    await sodium.ready;
    const email = process.env.MTAYLOR_IO_EMAIL;
    const secretKey = sodium.from_base64(
      process.env.MTAYLOR_IO_SECRET_KEY, sodium.base64_variants.ORIGINAL);

    const iam = await IAM.client(email, secretKey);
    const signature = iam.signature('request-id', 'GET', '/path');

    expect(signature).toBeDefined();
  });

  it('should create a URL', async () => {
    await sodium.ready;
    const email = process.env.MTAYLOR_IO_EMAIL;
    const secretKey = sodium.from_base64(
      process.env.MTAYLOR_IO_SECRET_KEY, sodium.base64_variants.ORIGINAL);

    const iam = await IAM.client(email, secretKey);
    const url = iam.url('/path');

    expect(url).toBe('https://iam.mtaylor.io/path');
  });

  it('should create a user', async () => {
    await sodium.ready;
    const email = process.env.MTAYLOR_IO_EMAIL;
    const secretKey = sodium.from_base64(
      process.env.MTAYLOR_IO_SECRET_KEY, sodium.base64_variants.ORIGINAL);

    const iam = await IAM.client(email, secretKey);
    const users = new Users(iam);
    const createUserResponse = await users.createUser()

    expect(createUserResponse).toBeDefined();
    expect(createUserResponse.keypair).toBeDefined();
    expect(createUserResponse.user).toBeDefined();

    users.deleteUser(createUserResponse.user.id)
  });

  it('should get a user', async () => {
    await sodium.ready;
    const email = process.env.MTAYLOR_IO_EMAIL;
    const secretKey = sodium.from_base64(
      process.env.MTAYLOR_IO_SECRET_KEY, sodium.base64_variants.ORIGINAL);

    const iam = await IAM.client(email, secretKey);
    const users = new Users(iam);
    const createUserResponse = await users.createUser()
    const user = await users.getUser(createUserResponse.user.id)

    expect(user).toBeDefined();

    users.deleteUser(createUserResponse.user.id)
  });

  it('should list users', async () => {
    await sodium.ready;
    const email = process.env.MTAYLOR_IO_EMAIL;
    const secretKey = sodium.from_base64(
      process.env.MTAYLOR_IO_SECRET_KEY, sodium.base64_variants.ORIGINAL);

    const iam = await IAM.client(email, secretKey);
    const users = new Users(iam);
    const userList = await users.listUsers()

    expect(userList).toBeDefined();
  });
});
