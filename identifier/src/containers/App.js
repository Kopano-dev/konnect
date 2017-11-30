import React, { Component } from 'react';
import { connect } from 'react-redux';
import injectTapEventPlugin from 'react-tap-event-plugin';
import { BrowserRouter, Switch, Route } from 'react-router-dom';
import Snackbar from 'material-ui/Snackbar';
import Button from 'material-ui/Button';
import PropTypes from 'prop-types';
import renderIf from 'render-if';

import { enhanceBodyBackground } from '../utils';
import Loginscreen from '../components/Loginscreen';
import Welcomescreen from '../components/Welcomescreen';
import PrivateRoute from '../components/PrivateRoute';

// Needed for onTouchTap
// http://stackoverflow.com/a/34015469/988941
injectTapEventPlugin();

// Trigger loading of background image.
enhanceBodyBackground();

class App extends Component {
  render() {
    const { hello, updateAvailable } = this.props;

    return (
      <div>
        <BrowserRouter className="App" basename="/signin/v1">
          <Switch>
            <PrivateRoute path="/welcome" exact component={Welcomescreen} hello={hello}></PrivateRoute>
            <Route path="/" component={Loginscreen}></Route>
          </Switch>
        </BrowserRouter>
        {renderIf(updateAvailable)(() => (
          <Snackbar
            anchorOrigin={{ vertical: 'bottom', horizontal: 'left'}}
            open
            action={<Button color="accent" dense onClick={(event) => this.reload(event)}>
              Reload
            </Button>}
            SnackbarContentProps={{
              'aria-describedby': 'message-id'
            }}
            message={<span id="message-id">Update available</span>}
          />
        ))}
      </div>
    );
  }

  reload(event) {
    event.preventDefault();

    window.location.reload();
  }
}

App.propTypes = {
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

export default connect(mapStateToProps)(App);
