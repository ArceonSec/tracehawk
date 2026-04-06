/**
 * Tracehawk frontend configuration.
 * 
 * For local dev:   API runs at http://localhost:8000
 * For Docker:      Both containers share the same Docker network,
 *                  but the browser still hits localhost:8000.
 */
export const API_URL = 'http://localhost:8000';
export const API_KEY = 'dev-local-key-changeme';
