import React from 'react';
import ReactDOM from 'react-dom';
import Loadable from 'react-loadable';
import PropTypes from 'prop-types';
import { Provider } from 'react-redux';

import { MuiThemeProvider } from 'material-ui/styles';

import store from './store';
import { unregister } from './registerServiceWorker';
import theme from './theme';

function LoadingComponent(props) {
  if (props.error) {
    // When the loader has errored.
    return <div id="loader">Error!</div>;
  } else if (props.timedOut) {
    // When the loader has taken longer than the timeout.
    return <div id="loader">Taking a long time...</div>;
  } else if (props.pastDelay) {
    // When the loader has taken longer than the delay.
    return <div id="loader">Loading...</div>;
  } else {
    // When the loader has just started.
    return null;
  }
}

LoadingComponent.propTypes = {
  error: PropTypes.bool,
  timedOut: PropTypes.bool,
  pastDelay: PropTypes.bool
};

// NOTE(longsleep): Load async with loader, this enables code splitting via Webpack.
const LoadableApp = Loadable({
  loader: () => import(/* webpackChunkName: "identifier-container" */ './containers/App'),
  loading: LoadingComponent,
  timeout: 20000
});

ReactDOM.render(
  <Provider store={store}>
    <MuiThemeProvider theme={theme}>
      <LoadableApp />
    </MuiThemeProvider>
  </Provider>,
  document.getElementById('root')
);

unregister();
