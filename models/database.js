const Joi = require('joi');

module.exports = {
	Member: {
		id: Joi.number().required(),
		name: Joi.string().max(255).required(),
		email: Joi.string().email().max(512).required(),
		password: Joi.string().required(),
		salt: Joi.string().required(),
		phone: Joi.string().max(64),
		avatar_url: Joi.string().max(255),
		country: Joi.string().max(255),
		address: Joi.string().max(255),
		city: Joi.string().max(255),
		state: Joi.string().max(255),
		zip_code: Joi.string().max(64),
		disabled: Joi.number(),
		created: Joi.date()
	},
	MemberPermission: {
		id: Joi.number().required(),
	}
};
