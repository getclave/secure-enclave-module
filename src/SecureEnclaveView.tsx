import { requireNativeViewManager } from 'expo-modules-core';
import * as React from 'react';

import { SecureEnclaveViewProps } from './SecureEnclave.types';

const NativeView: React.ComponentType<SecureEnclaveViewProps> =
  requireNativeViewManager('SecureEnclave');

export default function SecureEnclaveView(props: SecureEnclaveViewProps) {
  return <NativeView {...props} />;
}
