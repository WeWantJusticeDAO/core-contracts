/* global ethers, network */
import { ethers, network } from 'hardhat';
import { BigNumber, providers } from 'ethers';

export async function setTime(timestamp: number) {
  await ethers.provider.send('evm_setNextBlockTimestamp', [timestamp]);
}

export async function takeSnapshot() {
  return ethers.provider.send('evm_snapshot', []);
}

export async function revertSnapshot(id: string) {
  return ethers.provider.send('evm_revert', [id]);
}

export async function advanceTime(sec: number) {
  const now = (await ethers.provider.getBlock('latest')).timestamp;
  await setTime(now + sec);
}

export async function getSignerFromAddress(address: string) {
  await network.provider.request({
    method: 'hardhat_impersonateAccount',
    params: [address],
  });

  return ethers.provider.getSigner(address);
}

