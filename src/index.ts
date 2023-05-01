import { NativeModulesProxy, EventEmitter, Subscription } from 'expo-modules-core';

// Import the native module. On web, it will be resolved to SecureEnclave.web.ts
// and on native platforms to SecureEnclave.ts
import SecureEnclaveModule from './SecureEnclaveModule';
import SecureEnclaveView from './SecureEnclaveView';
import { ChangeEventPayload, SecureEnclaveViewProps } from './SecureEnclave.types';

// Get the native constant value.
export const PI = SecureEnclaveModule.PI;

export function hello(): string {
  return SecureEnclaveModule.hello();
}

export async function setValueAsync(value: string) {
  return await SecureEnclaveModule.setValueAsync(value);
}

const emitter = new EventEmitter(SecureEnclaveModule ?? NativeModulesProxy.SecureEnclave);
/**
	@returns Public key for the alias
	@dev Prompts for biometrics
	@throws If there's no public key for the alias
*/
export async function getPublicKey(alias: string): Promise<string> {
    return await SecureEnclaveModule.getPublicKey(alias);
}


export function addChangeListener(listener: (event: ChangeEventPayload) => void): Subscription {
  return emitter.addListener<ChangeEventPayload>('onChange', listener);
}

export { SecureEnclaveView, SecureEnclaveViewProps, ChangeEventPayload };
