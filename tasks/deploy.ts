import { BytesLike } from 'ethers';
import { ethers, artifacts } from 'hardhat';

const EIP_DEPLOYER = '0xce0042B868300000d44A59004Da54A005ffdcf9f';
const SALT = '0x0000000000000000000000000000000000000000000000000000000029c07104';

const BUMP_GAS_PRECENT = 130;
const DEFAULT_GAS_LIMIT = 2500000;

const defaultGasParams = {
  // gasPrice: 180e9,
  maxFeePerGas: 40e9,
  maxPriorityFeePerGas: 5e9,
};

import proxyArtifact from './InitializableAdminUpgradeabilityProxy.json';

async function deploy() {
  const proxyAddress = '0x000000c6a7c2141afc9c084eB1162972f4C25949';
  const proxyAdminAddress = await deployProxyAdmin();
  const donateAddress = await deployDonate();

  const proxy = await ethers.getContractAt('InitializableAdminUpgradeabilityProxy', proxyAddress);
  const donate = await ethers.getContractAt('Donate', donateAddress);

  await proxy['initialize(address,address,bytes)'](
    donateAddress,
    proxyAdminAddress,
    donate.interface.encodeFunctionData('initialize', ['0x111111f657d61c800B6BE4CD3b30C185EF066C8F', '0xDde03837E2291bD72C7a739Bc632940b551A9BC4'])
  );
}

async function deployDonate() {
  const address = await _deploy('Donate', []);
  console.log(`Donate: ${address}`);
  return address;
}

async function deployProxyAdmin() {
  const address = await _deploy('ProxyAdmin', []);
  console.log(`ProxyAdmin: ${address}`);
  return address;
}

async function deployProxy() {
  const bytecode = await getDeployByteCode(proxyArtifact.abi, proxyArtifact.bytecode, []);
  const expectedAddress = getAddress(bytecode);

  // deploy contracts
  await deployCreate2(expectedAddress, bytecode);
  console.log(`${proxyArtifact.contractName}: ${expectedAddress}`);
  return expectedAddress;
}


async function deployCreate2(expectedAddress: string, bytecode: BytesLike) {
  const code = await ethers.provider.getCode(expectedAddress, 'latest');

  // is contract return
  if (code && code !== '0x') {
    return;
  }
  const deployer = await ethers.getContractAt('SingletonFactory', EIP_DEPLOYER);
  const [sender] = await ethers.getSigners();

  try {
    console.log(`Deploying to (${expectedAddress})`);
    const tx = await deployer.connect(sender).deploy(bytecode, SALT, {
      gasLimit: DEFAULT_GAS_LIMIT,
      ...defaultGasParams,
    });
    await tx.wait(3);
  } catch (error) {
    console.error('Failed to deploy', error);
  }
}

async function getDeployByteCode(abi: any, bytecode: string, args: any[]) {
  let _bytecode = bytecode;

  if (args.length != 0) {
    const factory = new ethers.ContractFactory(abi, bytecode);
    const { data } = factory.getDeployTransaction(...args);

    if (!data) {
      throw new Error('Deploy transaction with no data. Something is very wrong');
    }

    _bytecode = data.toString();
  }

  return _bytecode;
}

export const buildBytecode = (constructorTypes: any[], constructorArgs: any[], contractBytecode: string) => {
  return `${contractBytecode}${encodeParams(constructorTypes, constructorArgs).slice(2)}`;
};

export const encodeParams = (dataTypes: any[], data: any[]) => {
  const abiCoder = ethers.utils.defaultAbiCoder;
  return abiCoder.encode(dataTypes, data);
};

export const getAddress = (bytecode: string) => {
  return `0x${ethers.utils
    .keccak256(
      `0x${['ff', EIP_DEPLOYER, SALT, ethers.utils.keccak256(bytecode)].map(x => x.replace(/0x/, '')).join('')}`,
    )
    .slice(-40)}`.toLowerCase();
};

async function _deploy(name: string, args: any[]) {
  const [sender] = await ethers.getSigners();
  console.log(`Deploying:${name}, args:${args}`);

  try {
    const factory = await ethers.getContractFactory(name);
    const contract = await factory.connect(sender).deploy(...args, {
      gasLimit: 2500000,
      ...defaultGasParams,
    });
    await contract.deployed();
    console.log(`Deployed ${name}:${contract.address}`);

    return contract.address;
  } catch (err) {
    console.log('error deploy', err);
    throw new Error('error deploy');
  }
}

deploy()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
