import * as React from 'react';

import { SecureEnclaveViewProps } from './SecureEnclave.types';

export default function SecureEnclaveView(props: SecureEnclaveViewProps) {
  return (
    <div>
      <span>{props.name}</span>
    </div>
  );
}
