import axios from 'axios';
import queryString from 'query-string';

import * as types from './action-types';

export function updateInput(name, value) {
  return {
    type: types.UPDATE_INPUT,
    name,
    value
  };
}

export function receiveValidateLogon(errors) {
  return {
    type: types.RECEIVE_VALIDATE_LOGON,
    errors
  };
}

export function requestLogon(username, password) {
  return {
    type: types.REQUEST_LOGON,
    username,
    password
  };
}

export function receiveLogon(state, errors=null) {
  return {
    type: types.RECEIVE_LOGON,
    state,
    errors
  };
}

export function executeLogon(username, password) {
  return function(dispatch) {
    dispatch(requestLogon(username, password));

    const r = {
      state: Math.random().toString(36).substring(7),
      params: [username, password, '1']
    };
    return axios.post('./identifier/_/logon', r, {
      headers: {
        'Kopano-Konnect-XSRF': '1'
      }
    }).then(response => {
      switch (response.status) {
        case 200:
          // success.
          return response.data;
        case 204:
          // login failed.
          return {
            success: false,
            state: response.headers['kopano-konnect-state'],
            errors: {
              http: new Error('Logon failed. Please verify your credentials and try again.')
            }
          };
        default:
          // error.
          throw new Error('Unexpected http response: ' + response.status);
      }
    }).then(response => {
      if (response.state !== r.state) {
        throw new Error('Unexpected response state: ' + response.state);
      }

      dispatch(receiveLogon(response.success === true, response.errors ? response.errors : null));
      return Promise.resolve(response);
    }).catch(error => {
      const errors = {
        http: error
      };

      dispatch(receiveValidateLogon(errors));
      return {
        success: false,
        errors: errors
      };
    });
  };
}

export function validateUsernamePassword(username, password, isSignedIn) {
  return function(dispatch) {
    return new Promise((resolve, reject) => {
      const errors = {};

      if (!username) {
        errors.username = 'Enter an username';
      }
      if (!password && !isSignedIn) {
        errors.password = 'Enter a password';
      }

      dispatch(receiveValidateLogon(errors));
      if (Object.keys(errors).length === 0) {
        resolve(errors);
      } else {
        reject(errors);
      }
    });
  };
}

export function executeLogonIfFormValid(username, password, isSignedIn) {
  return (dispatch) => {
    return dispatch(
      validateUsernamePassword(username, password, isSignedIn)
    ).then(() => {
      return dispatch(executeLogon(username, password));
    }).catch((errors) => {
      return {
        success: false,
        errors: errors
      };
    });
  };
}

export function advanceLogonFlow(state, history) {
  return (dispatch) => {
    const query = queryString.parse(history.location.search);

    if (query.oauth === '1') {
      if (query.continue && query.continue.indexOf(document.location.origin) === 0) {
        window.location.replace(query.continue);
        return;
      }
    }

    dispatch(receiveValidateLogon({})); // XXX(longsleep): hack to reset loading and errors.
    history.push('/welcome');
  };
}
