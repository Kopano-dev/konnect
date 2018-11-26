import React from 'react';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import { withStyles } from '@material-ui/core/styles';
import PropTypes from 'prop-types';
import Checkbox from '@material-ui/core/Checkbox';

const styles = () => ({
  row: {
    paddingTop: 0,
    paddingBottom: 0
  }
});

const ScopesList = ({scopes, meta, classes, ...rest}) => {
  const { mapping, definitions } = meta;

  const rows = [];
  const known = {};

  // TODO(longsleep): Sort scopes according to priority.
  for (let scope in scopes) {
    if (!scopes[scope]) {
      continue;
    }
    let id = mapping[scope];
    if (id) {
      if (known[id]) {
        continue;
      }
      known[id] = true;
    } else {
      id = scope;
    }
    let definition = definitions[id];
    let label ;
    if (!definition) {
      label = `Scope: ${scope}`;
    } else {
      label = definition.description;
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

ScopesList.propTypes = {
  classes: PropTypes.object.isRequired,

  scopes: PropTypes.object.isRequired,
  meta: PropTypes.object.isRequired
};

export default withStyles(styles)(ScopesList);
