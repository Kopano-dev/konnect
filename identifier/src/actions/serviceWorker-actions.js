import * as types from './action-types';

export function newContent() {
  return {
    type: types.SERVICE_WORKER_NEW_CONTENT
  };
}

export function readyForOfflineUse() {
  return {
    type: types.SERVICE_WORKER_READY
  };
}

export function registrationError(error) {
  return {
    type: types.SERVICE_WORKER_ERROR,
    error
  };
}

export function isOfflineMode() {
  return {
    type: types.SERVICE_WORKER_OFFLINE
  };
}
