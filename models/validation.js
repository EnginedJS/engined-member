const Joi = require('joi');

module.exports = {
	VerifyMember: {
		email: Joi.string().email().required(),
		password: Joi.string().required()
	},
	CreateMember: {
		name: Joi.string().required(),
		email: Joi.string().email().required(),
		password: Joi.string().required()
	},
	UpdateProfile: {
		email: Joi.string().email().required(),
		name: Joi.string().required(),
		phone: Joi.string(),
		country: Joi.string(),
		address: Joi.string(),
		city: Joi.string(),
		state: Joi.string(),
		zip_code: Joi.string()
	},
	SendPasswordResetEmail: {
		email: Joi.string().email().required()
	}
};
