import addDate from 'date-fns/add';
import PropTypes from 'prop-types';
import React from 'react';
import DatePicker from 'react-datepicker';
import { ErrorMessage, Field, Form, Formik } from 'formik';

import 'react-datepicker/dist/react-datepicker.css';

function calculateExpires({
  expiresType,
  expiresDate,
  expiresDuration,
  expiresUnit,
}) {
  if (expiresType === 'never') {
    return null;
  }
  if (expiresType === 'date') {
    return expiresDate;
  }
  const date = addDate(new Date(), { [expiresUnit]: expiresDuration });
  return Math.round(date.getTime() / 1000);
}

export default function CreateTokenForm({
  scopes,
  knownScopes,
  onCreateToken,
  onCancel,
}) {
  const now = new Date();

  return (
    <Formik
      initialValues={{
        name: '',
        scopes: [],
        expires: null,
        expiresDate: addDate(new Date(), { months: 1 }),
        expiresType: 'never',
        expiresDuration: 1,
        expiresUnit: 'months',
      }}
      validate={(values) => {
        const errors = {};
        if (!values.name) {
          errors.name = 'Required';
        } else if (values.name.length > 64) {
          errors.name = 'Must be 64 characters or less';
        }
        values.expires = calculateExpires(values);
        return errors;
      }}
      onSubmit={async (values, { setSubmitting }) => {
        await onCreateToken(values);
        setSubmitting(false);
      }}
    >
      {({ values, handleChange, isSubmitting }) => (
        <Form>
          <label htmlFor="create-token-name">Name:</label>{' '}
          <Field
            id="create-token-name"
            name="name"
            type="text"
            maxlength="64"
            placeholder="token name"
          />
          <ErrorMessage name="name" component="div" />
          <br />
          <div id="create-token-scopes-label">Scopes:</div>{' '}
          <div
            role="group"
            id="create-token-scopes"
            aria-labelledby="create-token-scopes-label"
          >
            {knownScopes.map(({ name, description }) => {
              if (!scopes.includes(name)) return;
              return (
                <>
                  <label>
                    <Field type="checkbox" name="scopes" value={name} />
                    <bold className="qa-scope-name">{name}</bold>: {description}
                  </label>
                  <br />
                </>
              );
            })}
          </div>
          <ErrorMessage name="scopes" component="div" />
          <br />
          <div id="create-token-expires-label">Expires:</div>{' '}
          <div
            role="group"
            id="create-token-expires"
            aria-labelledby="create-token-expires-label"
          >
            <label>
              <Field type="radio" name="expiresType" value="never" />
              Never
            </label>
            <label>
              <Field type="radio" name="expiresType" value="interval" />
              Choose lifetime
            </label>
            <label>
              <Field type="radio" name="expiresType" value="date" />
              Choose expiration date
            </label>
            {values.expiresType === 'interval' && (
              <>
                <br />
                <Field
                  type="number"
                  name="expiresDuration"
                  min="1"
                  max="99999"
                />
                <Field as="select" name="expiresUnit">
                  <option value="hours">hour(s)</option>
                  <option value="days">day(s)</option>
                  <option value="weeks">week(s)</option>
                  <option value="months">month(s)</option>
                  <option value="years">years(s)</option>
                </Field>
              </>
            )}
            {values.expiresType === 'date' && (
              <>
                <br />
                <DatePicker
                  name="expiresDate"
                  dateFormat="yyyy-MM-dd HH:mm"
                  minDate={now}
                  showTimeInput
                  timeInputLabel="Time:"
                  timeFormat="HH:mm"
                  selected={values.expiresDate}
                  onChange={handleChange}
                />
              </>
            )}
          </div>
          <ErrorMessage name="expires" component="div" />
          <br />
          <button type="submit" disabled={isSubmitting}>
            Create
          </button>
          <button type="button" disabled={isSubmitting} onClick={onCancel}>
            Cancel
          </button>
        </Form>
      )}
    </Formik>
  );
}
CreateTokenForm.propTypes = {
  scopes: PropTypes.arrayOf(PropTypes.string),
  knownScopes: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string,
      description: PropTypes.string,
    })
  ),
  onCreateToken: PropTypes.func.isRequired,
  onCancel: PropTypes.func.isRequired,
};
