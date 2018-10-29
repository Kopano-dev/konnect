import React, { PureComponent } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import { BrowserRouter, Switch, Route } from 'react-router-dom';

import { withStyles } from '@material-ui/core/styles';

import { enhanceBodyBackground } from '../utils';
import Loginscreen from '../components/Loginscreen';
import Welcomescreen from '../components/Welcomescreen';
import Goodbyescreen from '../components/Goodbyescreen';
import PrivateRoute from '../components/PrivateRoute';

// Trigger loading of background image.
enhanceBodyBackground();

const styles = () => ({
  root: {
    position: 'relative',
    display: 'flex',
    flex: 1
  }
});

class Identifier extends PureComponent {
  render() {
    const { classes, hello } = this.props;

    return (
      <div className={classes.root}>
        <BrowserRouter basename="/signin/v1">
          <Switch>
            <PrivateRoute path="/welcome" exact component={Welcomescreen} hello={hello}></PrivateRoute>
            <Route path="/goodbye" exact component={Goodbyescreen}></Route>
            <Route path="/" component={Loginscreen}></Route>
          </Switch>
        </BrowserRouter>
      </div>
    );
  }

  reload(event) {
    event.preventDefault();

    window.location.reload();
  }
}

Identifier.propTypes = {
  classes: PropTypes.object.isRequired,

  hello: PropTypes.object,
  updateAvailable: PropTypes.bool.isRequired
};

const mapStateToProps = (state) => {
  const { hello, updateAvailable } = state.common;

  return {
    hello,
    updateAvailable
  };
};

export default connect(mapStateToProps)(withStyles(styles)(Identifier));
