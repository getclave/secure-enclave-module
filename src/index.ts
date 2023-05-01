import {
    EventEmitter,
    NativeModulesProxy,
    Subscription,
} from 'expo-modules-core';

import {
    ChangeEventPayload,
    SecureEnclaveViewProps,
} from './SecureEnclave.types';
// Import the native module. On web, it will be resolved to SecureEnclave.web.ts
// and on native platforms to SecureEnclave.ts
import SecureEnclaveModule from './SecureEnclaveModule';
import SecureEnclaveView from './SecureEnclaveView';

// Get the native constant value.
export const PI = SecureEnclaveModule.PI;

export function hello(): string {
    return SecureEnclaveModule.hello();
}

export async function setValueAsync(value: string) {
    return await SecureEnclaveModule.setValueAsync(value);
}

/**
	@returns Public key for the alias
	@dev Prompts for biometrics
	@throws If there's no public key for the alias
*/
export async function getPublicKey(alias: string): Promise<string> {
    return await SecureEnclaveModule.getPublicKey(alias);
}

/**
	@description Generates a key pair for a alias
    @dev If there's a pair already, this function will override the existing one
	@dev Prompts for biometrics
	@returns Key pair's public key
	@throws If key generation fails
*/
export async function generateKeyPair(alias: string): Promise<string> {
    return await SecureEnclaveModule.generateKeyPair(alias);
}

/**
	@description Deletes a key pair corresponding to a alias
	@dev Prompts for biometrics
	@throws If there's no key pair for the alias
*/
export async function deleteKeyPair(alias: string): Promise<void> {
    return await SecureEnclaveModule.deleteKeyPair(alias);
}

const emitter = new EventEmitter(
    SecureEnclaveModule ?? NativeModulesProxy.SecureEnclave,
);

export function addChangeListener(
    listener: (event: ChangeEventPayload) => void,
): Subscription {
    return emitter.addListener<ChangeEventPayload>('onChange', listener);
}

export { SecureEnclaveView, SecureEnclaveViewProps, ChangeEventPayload };
