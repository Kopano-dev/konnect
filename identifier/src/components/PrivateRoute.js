import React from 'react';
import PropTypes from 'prop-types';
import { Route, Redirect } from 'react-router-dom';

const PrivateRoute = ({ component: Target, hello, ...rest }) => (
  <Route {...rest} render={props => (
    hello ? (
      <Target {...props}/>
    ) : (
      <Redirect to={{
        pathname: '/identifier'
      }}/>
    )
  )}/>
);

PrivateRoute.propTypes = {
  component: PropTypes.func.isRequired,
  hello: PropTypes.object
};

export default PrivateRoute;
