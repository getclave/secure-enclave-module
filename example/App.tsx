import { Button, StyleSheet, View } from 'react-native';
import * as SecureEnclave from 'secure-enclave';
global.Buffer = require('buffer').Buffer;
/**
 * Test the secure enclave functionality.
 */

    const alias = 'com.clave.test.enclave'; 

    const userOpHash = "0xeae1338ffe1cc6c72f6f87ee8ae9f05277fe858035370fcc3f89ef29ae227808"

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
