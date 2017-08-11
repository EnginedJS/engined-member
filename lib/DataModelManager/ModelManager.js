
module.exports = class {

	constructor(models) {

		this.models = models || {};
	}

	define(models) {
		this.models = models || {};
	}

	getModels() {
		return this.models;
	}

	getModel(modelName) {
		return this.models[modelName];
	};

	setModel(modelName, schema) {
		this.models[modelName] = schema;
	};

	updateModel(modelName, schema) {

		// Getting specific model
		const model = this.getModel(modelName);
		if (model === undefined)
			throw new Error('No such data model \"' + modelName + '\"');

		// Update than replace old one
		this.setModel(Object.assign(model, schema));
	}
};
