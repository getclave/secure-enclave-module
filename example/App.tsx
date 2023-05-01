import { StyleSheet, Text, View } from 'react-native';

import * as SecureEnclave from 'secure-enclave';

export default function App() {
  return (
    <View style={styles.container}>
      <Text>{SecureEnclave.hello()}</Text>
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
