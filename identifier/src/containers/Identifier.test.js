import React from 'react';
import ReactDOM from 'react-dom';

import Identifier from './Identifier';

it('renders without crashing', () => {
  const div = document.createElement('div');
  ReactDOM.render(<Identifier />, div);
});
