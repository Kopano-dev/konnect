import './index.css';
import 'typeface-roboto';

import * as version from './version';

console.info(`Kopano Identifier build version: ${version.build}`); // eslint-disable-line no-console

// NOTE(longsleep): Load async, this enables code splitting via Webpack.
import(/* webpackChunkName: "identifier-app" */ './app');
