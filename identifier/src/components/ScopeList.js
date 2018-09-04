import React from 'react';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import { withStyles } from '@material-ui/core/styles';
import PropTypes from 'prop-types';
import Checkbox from '@material-ui/core/Checkbox';

const scopesMap = {
  'openid': 'basic',
  'email': 'basic',
  'profile': 'basic',

  'konnect/id': 'basic',
  'konnect/uuid': 'basic',
  'konnect/hashed_sub': 'basic',
  'konnect/raw_sub': 'basic',

  'kopano/gc': 'kopano/gc'
};

const descriptionMap = {
  'basic': 'Access your basic account information',
  'offline_access': 'Keep the allowed access persistently and forever',

  'kopano/gc': 'Read and write your Kopano Groupware data'
};

const styles = () => ({
  row: {
    paddingTop: 0,
    paddingBottom: 0
  }
});

const ScopeList = ({scopes, classes, ...rest}) => {
  const rows = [];
  const known = {};

  for (let scope in scopes) {
    if (!scopes[scope]) {
      continue;
    }
    let id = scopesMap[scope];
    if (id) {
      if (known[id]) {
        continue;
      }
      known[id] = true;
    } else {
      id = scope;
    }
    let label = descriptionMap[id];
    if (!label) {
      label = `Scope: ${scope}`;
    }

    rows.push(
      <ListItem
        disableGutters
        dense
        key={id}
        className={classes.row}
      ><Checkbox
          checked
          disableRipple
          disabled
        />
        <ListItemText primary={label} />
      </ListItem>
    );
  }

  return (
    <List {...rest}>
      {rows}
    </List>
  );
};

ScopeList.propTypes = {
  classes: PropTypes.object.isRequired,

  scopes: PropTypes.object.isRequired
};

export default withStyles(styles)(ScopeList);
