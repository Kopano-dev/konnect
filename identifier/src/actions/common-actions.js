import axios from 'axios';

import * as types from './action-types';

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

export function receiveHello(state, username, displayName) {
  return {
    type: types.RECEIVE_HELLO,
    state,
    username,
    displayName
  };
}

export function executeHello(prompt=false) {
  return function(dispatch) {
    dispatch(resetHello());

    const r = {
      state: Math.random().toString(36).substring(7),
      prompt: prompt
    };

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

      dispatch(receiveHello(response.success === true, response.username, response.displayName));
      return Promise.resolve(response);
    }).catch(error => {
      dispatch(receiveError(error));
    });
  };
}

export function retryHello(prompt=false) {
  return function(dispatch) {
    dispatch(receiveError(null));

    return dispatch(executeHello(prompt));
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
    dispatch(requestLogoff());

    const r = {
      state: Math.random().toString(36).substring(7)
    };

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
