<?php

/**
 * WebSocket abstract class
 *
 * @author Aya Mishina <http://fei-yen.jp/maya/> (Define abstract class)
 */
abstract class WebSocket
{
	// protected members {
		protected $options = array();
	// }

	// public methods {
		/**
		 * Get option
		 *
		 * @param string $key key name
		 * @param mixed $default Return this value if option is undefined.
		 * @return mixed Return null when option and default are undefined.
		 */
		public function getOption($key, $default = null) {
			settype($key, 'string');

			$options = $this->getOptions();
			if(! isset($options[$key])) return $default;
			return $options[$key];
		}
		/**
		 * Set one option
		 *
		 * @param string $key key name
		 * @param mixed $value Option value to set.
		 * @return void
		 */
		public function setOption($key, $value) {
			settype($key, 'string');

			$options = $this->getOptions();
			$options[$key] = $value;

			$this->options = $options;
		}
		/**
		 * Get all options
		 *
		 * @return array
		 */
		public function getOptions() {
			return is_array($this->options) ? $this->options : array();
		}
		/**
		 * Set multi options
		 *
		 * @param array $options Options array, key is option name.
		 * @return void
		 */
		public function setOptions(array $options) {
			$this->options = array_merge($this->getOptions(), $options);
		}
	// }
}
