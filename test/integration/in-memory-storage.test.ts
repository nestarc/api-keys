import { InMemoryApiKeyStorage } from '../../src/storage/in-memory-storage';
import { storageContract } from '../contract/storage-contract';

storageContract('InMemoryApiKeyStorage', () => new InMemoryApiKeyStorage());
