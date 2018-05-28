import axios from 'axios';

import * as types from './action-types';
import { newHelloRequest } from '../models/hello';
import { withClientRequestState } from '../utils';

export function receiveError(error) {
  return {
    type: types.RECEIVE_ERROR,
    error
  };
}

export function resetHello() {
  return {
    type: types.RESET_HELLO
  };
}

export function receiveHello(hello) {
  const { success, username, displayName } = hello;

  return {
    type: types.RECEIVE_HELLO,
    state: success === true,
    username,
    displayName,
    hello
  };
}

export function executeHello() {
  return function(dispatch, getState) {
    dispatch(resetHello());

    const { flow, query } = getState().common;

    const r = withClientRequestState(newHelloRequest(flow, query));
    return axios.post('./identifier/_/hello', r, {
      headers: {
        'Kopano-Konnect-XSRF': '1'
      }
    }).then(response => {
      switch (response.status) {
        case 200:
          // success.
          return response.data;
        case 204:
          // not signed-in.
          return {
            success: false,
            state: response.headers['kopano-konnect-state']
          };
        default:
          // error.
          throw new Error('Unexpected http response: ' + response.status);
      }
    }).then(response => {
      if (response.state !== r.state) {
        throw new Error('Unexpected response state: ' + response.state);
      }

      dispatch(receiveHello(response));
      return Promise.resolve(response);
    }).catch(error => {
      dispatch(receiveError(error));
    });
  };
}

export function retryHello() {
  return function(dispatch) {
    dispatch(receiveError(null));

    return dispatch(executeHello());
  };
}

export function requestLogoff() {
  return {
    type: types.REQUEST_LOGOFF
  };
}

export function receiveLogoff(state) {
  return {
    type: types.RECEIVE_LOGOFF,
    state
  };
}

export function executeLogoff() {
  return function(dispatch) {
    dispatch(resetHello());
    dispatch(requestLogoff());

    const r = withClientRequestState({});
    return axios.post('./identifier/_/logoff', r, {
      headers: {
        'Kopano-Konnect-XSRF': '1'
      }
    }).then(response => {
      switch (response.status) {
        case 200:
          // success.
          return response.data;
        default:
          // error.
          throw new Error('Unexpected http response: ' + response.status);
      }
    }).then(response => {
      if (response.state !== r.state) {
        throw new Error('Unexpected response state: ' + response.state);
      }

      dispatch(receiveLogoff(response.success === true));
      return Promise.resolve(response);
    }).catch(error => {
      dispatch(receiveError(error));
    });
  };
}
