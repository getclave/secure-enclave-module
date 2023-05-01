import { Button, StyleSheet, View } from 'react-native';
import * as SecureEnclave from 'secure-enclave';

/**
 * Test the secure enclave functionality.
 */
async function testEnclave(): Promise<void> {
    const alias = 'com.clave.test.enclave';
    const message = 'Hello, world!';

    try {
        await SecureEnclave.getPublicKey(alias);
    } catch {
        console.log('getPublicKey() failed, as expected');
    }

    try {
        await SecureEnclave.deleteKeyPair(alias);
    } catch {
        console.log('deleteKeyPair() failed, as expected');
    }

    try {
        await SecureEnclave.signMessage(alias, message);
    } catch {
        console.log('signMessage() failed, as expected');
    }

    const pubKey = await SecureEnclave.generateKeyPair(alias);
    console.log(`Generated key pair, public key: ${pubKey}`);

    const signature = await SecureEnclave.signMessage(alias, message);
    console.log(`Signed message, signature: ${signature}`);

    await SecureEnclave.deleteKeyPair(alias);
    console.log('Deleted key pair');

    try {
        await SecureEnclave.getPublicKey(alias);
    } catch {
        console.log('getPublicKey() failed, as expected');
    }
}

export default function App(): JSX.Element {
    return (
        <View style={styles.container}>
            <Button title="Test Enclave" onPress={testEnclave} />
        </View>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#fff',
        alignItems: 'center',
        justifyContent: 'center',
    },
});
