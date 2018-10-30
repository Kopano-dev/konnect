import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import renderIf from 'render-if';
import { FormattedMessage } from 'react-intl';

import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import Tooltip from '@material-ui/core/Tooltip';
import CircularProgress from '@material-ui/core/CircularProgress';
import green from '@material-ui/core/colors/green';
import Typography from '@material-ui/core/Typography';
import DialogActions from '@material-ui/core/DialogActions';

import { executeConsent, advanceLogonFlow, receiveValidateLogon } from '../actions/login-actions';
import { ErrorMessage } from '../errors';
import { REQUEST_CONSENT_ALLOW } from '../actions/action-types';
import ClientDisplayName from './ClientDisplayName';
import ScopeList from './ScopeList';

const styles = theme => ({
  button: {
    margin: theme.spacing.unit
  },
  buttonProgress: {
    color: green[500],
    position: 'absolute',
    top: '50%',
    left: '50%',
    marginTop: -12,
    marginLeft: -12
  },
  subHeader: {
    marginBottom: theme.spacing.unit * 2
  },
  scopeList: {
    marginBottom: theme.spacing.unit * 2
  },
  wrapper: {
    marginTop: theme.spacing.unit * 5,
    position: 'relative',
    display: 'inline-block'
  },
  message: {
    marginTop: theme.spacing.unit * 2
  }
});

class Consent extends Component {
  componentDidMount() {
    const { dispatch, hello, history, client } = this.props;
    if ((!hello || !hello.state || !client) && history.action !== 'PUSH') {
      history.replace(`/identifier${history.location.search}${history.location.hash}`);
    }

    dispatch(receiveValidateLogon({})); // XXX(longsleep): hack to reset loading and errors.
  }

  render() {
    const { classes, loading, hello, errors, client } = this.props;

    const scopes = hello.details.scopes || {};
    return (
      <div>
        <Typography variant="headline" component="h3">
          <FormattedMessage
            id="konnect.consent.headline"
            defaultMessage="Hi {displayName}"
            values={{displayName: hello.displayName}}>
          </FormattedMessage>
        </Typography>
        <Typography variant="subheading" className={classes.subHeader}>
          {hello.username}
        </Typography>

        <Typography variant="subheading" gutterBottom>
          <FormattedMessage
            id="konnect.consent.message"
            defaultMessage="{clientDisplayName} wants to"
            values={{clientDisplayName:
              <Tooltip
                placement="bottom"
                title={<FormattedMessage
                  id="konnect.consent.tooltip.client"
                  defaultMessage='Clicking "Allow" will redirect you to: {redirectURI}'
                  values={{
                    redirectURI: client.redirect_uri
                  }}
                ></FormattedMessage>}
              >
                <em><ClientDisplayName client={client}/></em>
              </Tooltip>
            }}
          ></FormattedMessage>
        </Typography>
        <ScopeList dense disablePadding className={classes.scopeList} scopes={scopes}></ScopeList>

        <Typography variant="subheading" gutterBottom>
          <FormattedMessage
            id="konnect.consent.question"
            defaultMessage="Allow {clientDisplayName} to do this?"
            values={{
              clientDisplayName: <em><ClientDisplayName client={client}/></em>
            }}
          ></FormattedMessage>
        </Typography>
        <Typography color="secondary">
          <FormattedMessage
            id="konnect.consent.consequence"
            defaultMessage="By clicking Allow, you allow this app to use your information.">
          </FormattedMessage>
        </Typography>

        <form action="" onSubmit={(event) => this.logon(event)}>
          <DialogActions>
            <div className={classes.wrapper}>
              <Button
                color="secondary"
                className={classes.button}
                disabled={!!loading}
                onClick={(event) => this.action(event, false)}
              >
                <FormattedMessage id="konnect.consent.cancelButton.label" defaultMessage="Cancel"></FormattedMessage>
              </Button>
              {(loading && loading !== REQUEST_CONSENT_ALLOW) &&
                <CircularProgress size={24} className={classes.buttonProgress} />}
            </div>
            <div className={classes.wrapper}>
              <Button
                type="submit"
                color="primary"
                className={classes.button}
                disabled={!!loading}
                onClick={(event) => this.action(event, true)}
              >
                <FormattedMessage id="konnect.consent.allowButton.label" defaultMessage="Allow"></FormattedMessage>
              </Button>
              {loading === REQUEST_CONSENT_ALLOW && <CircularProgress size={24} className={classes.buttonProgress} />}
            </div>
          </DialogActions>

          {renderIf(errors.http)(() => (
            <Typography variant="body1" color="error" className={classes.message}>
              <ErrorMessage error={errors.http}></ErrorMessage>
            </Typography>
          ))}
        </form>
      </div>
    );
  }

  action(event, allow=false) {
    event.preventDefault();

    const { dispatch, history } = this.props;
    dispatch(executeConsent(allow)).then((response) => {
      if (response.success) {
        dispatch(advanceLogonFlow(response.success, history, true, {konnect: response.state}));
      }
    });
  }
}

Consent.propTypes = {
  classes: PropTypes.object.isRequired,

  loading: PropTypes.string.isRequired,
  errors: PropTypes.object.isRequired,
  hello: PropTypes.object,
  client: PropTypes.object.isRequired,

  dispatch: PropTypes.func.isRequired,
  history: PropTypes.object.isRequired
};

const mapStateToProps = (state) => {
  const { hello } = state.common;
  const { loading, errors } = state.login;

  return {
    loading: loading,
    errors,
    hello,
    client: hello.details.client || {}
  };
};

export default connect(mapStateToProps)(withStyles(styles)(Consent));
