const Joi = require('joi');

module.exports = {
	GetLoginInfo: {
		schema: {
			id: 'Member.id',
			name: 'Member.name',
			email: 'Member.email'
		}
	},
	CreateMember: {
		schema: {
			email: 'Member.email',
			name: 'Member.name',
			password: 'Member.password'
		}
	},
	VerifyMember: {
		schema: {
			id: 'Member.id',
			name: 'Member.name',
			email: 'Member.email'
		}
	},
	GetProfile: {
		schema: {
			email: 'Member.email',
			name: 'Member.name',
			phone: 'Member.phone',
			avatar_url: 'Member.avatar_url',
			country: 'Member.country',
			address: 'Member.address',
			city: 'Member.city',
			state: 'Member.state',
			zip_code: 'Member.zip_code',
			created: 'Member.created'
		}
	},
	UpdateProfile: {
		schema: {
			email: 'Member.email',
			name: 'Member.name',
			phone: 'Member.phone',
			country: 'Member.country',
			address: 'Member.address',
			city: 'Member.city',
			state: 'Member.state',
			zip_code: 'Member.zip_code'
		}
	},
	GetFullProfile: {
		schema: {
			id: 'Member.id',
			email: 'Member.email',
			name: 'Member.name',
			phone: 'Member.phone',
			avatar_url: 'Member.avatar_url',
			country: 'Member.country',
			address: 'Member.address',
			city: 'Member.city',
			state: 'Member.state',
			zip_code: 'Member.zip_code',
			disabled: 'Member.disabled',
			created: 'Member.created'
		}
	},
	ListMembers: {
		schema: {
			id: 'Member.id',
			email: 'Member.email',
			name: 'Member.name',
			avatar_url: 'Member.avatar_url',
			disabled: 'Member.disabled',
			created: 'Member.created'
		}
	}
};
