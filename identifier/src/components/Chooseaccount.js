import React, { Component } from 'react';
import { connect } from 'react-redux';
import { withStyles } from '@material-ui/core/styles';
import PropTypes from 'prop-types';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import Typography from '@material-ui/core/Typography';

import { executeLogonIfFormValid, advanceLogonFlow } from '../actions/login-actions';

const styles = theme => ({
  subHeader: {
    marginBottom: theme.spacing.unit * 5
  },
  message: {
    marginTop: theme.spacing.unit * 2
  },
  accountList: {
    marginLeft: theme.spacing.unit * -3,
    marginRight: theme.spacing.unit * -3
  },
  accountListItem: {
    paddingLeft: theme.spacing.unit * 3,
    paddingRight: theme.spacing.unit * 3
  }
});

class Chooseaccount extends Component {
  componentDidMount() {
    const { hello, history } = this.props;
    if ((!hello || !hello.state) && history.action !== 'PUSH') {
      history.replace(`/identifier${history.location.search}${history.location.hash}`);
    }
  }

  render() {
    const { loading, errors, classes, hello } = this.props;

    let errorMessage = null;
    if (errors.http) {
      errorMessage = <Typography variant="body1" color="error" className={classes.message}>{errors.http.message}</Typography>;
    }

    let username = '';
    if (hello && hello.state) {
      username = hello.username;
    }

    return (
      <div>
        <Typography variant="headline" component="h3">
          Choose an account
        </Typography>
        <Typography variant="subheading" className={classes.subHeader}>
          to sign in to Kopano
        </Typography>

        <form action="" onSubmit={(event) => this.logon(event)}>
          <List disablePadding className={classes.accountList}>
            <ListItem
              button
              disableGutters
              className={classes.accountListItem}
              disabled={!!loading}
              onClick={(event) => this.logon(event)}
            ><Avatar>{username.substr(0, 1)}</Avatar>
              <ListItemText primary={username} />
            </ListItem>
            <ListItem
              button
              disableGutters
              className={classes.accountListItem}
              disabled={!!loading}
              onClick={(event) => this.logoff(event)}
            ><Avatar>?</Avatar>
              <ListItemText primary="Use another account" />
            </ListItem>
          </List>

          {errorMessage}
        </form>
      </div>
    );
  }

  logon(event) {
    event.preventDefault();

    const { hello, dispatch, history } = this.props;
    dispatch(executeLogonIfFormValid(hello.username, '', true)).then((response) => {
      if (response.success) {
        dispatch(advanceLogonFlow(response.success, history));
      }
    });
  }

  logoff(event) {
    event.preventDefault();

    const { history} = this.props;
    history.push(`/identifier${history.location.search}${history.location.hash}`);
  }
}

Chooseaccount.propTypes = {
  classes: PropTypes.object.isRequired,

  loading: PropTypes.string.isRequired,
  errors: PropTypes.object.isRequired,
  hello: PropTypes.object,

  dispatch: PropTypes.func.isRequired,
  history: PropTypes.object.isRequired
};

const mapStateToProps = (state) => {
  const { loading, errors } = state.login;
  const { hello } = state.common;

  return {
    loading,
    errors,
    hello
  };
};

export default connect(mapStateToProps)(withStyles(styles)(Chooseaccount));
