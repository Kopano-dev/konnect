import React from 'react';
import ReactDOM from 'react-dom';
import Loadable from 'react-loadable';
import { Provider } from 'react-redux';

import { MuiThemeProvider } from '@material-ui/core/styles';

import { defaultTheme as theme } from 'kpop/es/theme';
import IntlContainer from 'kpop/es/IntlContainer';
import Loading from 'kpop/es/Loading';
import { unregister } from 'kpop/es/serviceWorker';

import store from './store';
import translations from './locales';

// NOTE(longsleep): Load async with loader, this enables code splitting via Webpack.
const LoadableApp = Loadable({
  loader: () => import(/* webpackChunkName: "identifier-container" */ './containers/Identifier'),
  loading: Loading,
  timeout: 20000
});

ReactDOM.render(
  <Provider store={store}>
    <MuiThemeProvider theme={theme}>
      <IntlContainer messages={translations}>
        <LoadableApp />
      </IntlContainer>
    </MuiThemeProvider>
  </Provider>,
  document.getElementById('root')
);

unregister();
