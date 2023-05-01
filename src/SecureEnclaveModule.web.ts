import { EventEmitter } from 'expo-modules-core';
import type { NativeModule } from 'react-native/types';

const emitter = new EventEmitter({} as NativeModule);

export default {
    PI: Math.PI,
    async setValueAsync(value: string): Promise<void> {
        emitter.emit('onChange', { value });
    },
    hello(): string {
        return 'Hello world! 👋';
    },
};
