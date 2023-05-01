// Import the native module. On web, it will be resolved to SecureEnclave.web.ts
// and on native platforms to SecureEnclave.ts
import SecureEnclaveModule from './SecureEnclaveModule';

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

/**
	@description Signs a message using key pair of the alias
	@dev Prompts for biometrics
	@throws If there's no key pair for the alias
	@throws If signing fails
*/
export async function signMessage(
    alias: string,
    message: string,
): Promise<string> {
    return await SecureEnclaveModule.signMessage(alias, message);
}
