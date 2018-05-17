import 'kpop/es/styles/kpop';
import 'typeface-roboto';
import './app.css';

import * as kpop from 'kpop/es/version';

import * as version from './version';
import './fancy-background.css';

console.info(`Kopano Identifier build version: ${version.build}`); // eslint-disable-line no-console
console.info(`Kopano Kpop build version: ${kpop.build}`); // eslint-disable-line no-console

// NOTE(longsleep): Load async, this enables code splitting via Webpack.
import(/* webpackChunkName: "identifier-app" */ './identifier');
