const ModelManager = require('./ModelManager');

module.exports = class {

	constructor(models = {}) {

		this.database = new ModelManager(models.database || {});
		this.validation = new ModelManager(models.validation || {});
		this.view = new ModelManager(models.view || {});
	}

	defineDatabase(models) {
		this.database.define(models);
	}

	defineValidation(models) {
		this.validation.define(models);
	}

	defineView(models) {
		this.view.define(models);
	}
};
