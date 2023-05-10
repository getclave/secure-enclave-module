import { Button, StyleSheet, View } from 'react-native';
import * as SecureEnclave from 'secure-enclave';
global.Buffer = require('buffer').Buffer;
/**
 * Test the secure enclave functionality.
 */

    const alias = 'com.clave.test.enclave'; 

    const userOpHash = "0x78eb0915105bdaff0ed454fead104a29fefef4e093e447c3fed7dc51c7331400"

async function getPublic(): Promise<void> {
    try {
        const pubKey = await SecureEnclave.generateKeyPair(alias);
        console.log(`Generated key pair, public key: ${pubKey}`);
    } catch {
        console.log('generate key pair failed');
    }
}

async function signOp(): Promise<void> {
    const message = userOpHash.slice(2)
    console.log("userOpHash:"+message);
    try {
        const signature = await SecureEnclave.signMessage(alias, message);
        console.log(`Signed message, signature: ${signature}`);
    } catch {
        console.log('sign failed');
    }
}

async function deleteEnclave(): Promise<void> {
    try {
        await SecureEnclave.deleteKeyPair(alias);
        console.log('delete KeyPair');
    } catch {
        console.log('delete failed');
    }
}

export default function App(): JSX.Element {
    return (
        <View style={styles.container}>
            <Button title="Get Public key" onPress={getPublic} />

            <Button title="Sign userOp" onPress={signOp} />

            <Button title="Delete KeyPair" onPress={deleteEnclave} />
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
