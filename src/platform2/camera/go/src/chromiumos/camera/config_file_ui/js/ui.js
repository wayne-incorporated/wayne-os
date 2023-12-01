// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

function onSwitchInput(configId, optionId) {
  const configContainer =
      document.querySelector('#' + configId.concat('_container'));
  const checkbox =
      configContainer.querySelector('#' + optionId.concat('_checkbox'));
  let value = configContainer.querySelector('#' + optionId.concat('_value'));
  value.innerHTML = checkbox.checked;
  postOptionValues(configId);
}

function onTextInput(configId, optionId) {
  const configContainer =
      document.querySelector('#' + configId.concat('_container'));
  const text = configContainer.querySelector('#' + optionId.concat('_text'));
  let range = configContainer.querySelector('#' + optionId.concat('_range'));
  let value = configContainer.querySelector('#' + optionId.concat('_value'));
  range.value = text.value;
  value.innerHTML = text.value;
  postOptionValues(configId);
}

function onRangeInput(configId, optionId) {
  const configContainer =
      document.querySelector('#' + configId.concat('_container'));
  const range = configContainer.querySelector('#' + optionId.concat('_range'));
  let text = configContainer.querySelector('#' + optionId.concat('_text'));
  let value = configContainer.querySelector('#' + optionId.concat('_value'));
  text.value = range.value;
  value.innerHTML = text.value;
  postOptionValues(configId);
}

function onSelectInput(configId, optionId) {
  const configContainer =
      document.querySelector('#' + configId.concat('_container'));
  const select = configContainer.querySelector('#' + optionId.concat('_select'))
  let value = configContainer.querySelector('#' + optionId.concat('_value'));
  value.innerHTML = select.value;
  postOptionValues(configId);
}

function onTextareaInput(configId, optionId) {
  const configContainer =
      document.querySelector('#' + configId.concat('_container'));
  const textarea =
      configContainer.querySelector('#' + optionId.concat('_textarea'))
  let value = configContainer.querySelector('#' + optionId.concat('_value'));
  value.innerHTML = textarea.value;
  postOptionValues(configId);
}

async function postOptionValues(configId) {
  let results = {config: configId, options: {}};
  const configContainer =
      document.querySelector('#' + configId.concat('_container'));
  const options = configContainer.querySelectorAll('.option');
  for (let i = 0; i < options.length; ++i) {
    const optionId = options[i].querySelector('.option-name').id;
    const value = options[i].querySelector('.option-value').innerHTML;
    results.options[optionId] = value;
  }
  console.log(results);

  try {
    const response = await fetch('/', {
      method: 'POST',
      body: JSON.stringify(results),
      headers: new Headers({'Content-Type': 'application/json'})
    });
    console.log(response);
  } catch (error) {
    console.log(error);
    console.log(error.response);
    onOptionSubmitted(error.response.data);
  }
}

function submit(configId) {
  postOptionValues(configId);
  onOptionSubmitted('Config options updated');
}

function onOptionSubmitted(responsePrompt) {
  let modal = document.querySelector('#popUp');
  let span = document.querySelector('.close');
  let msg = document.querySelector('.modal-message');

  msg.innerHTML = responsePrompt;
  modal.style.display = 'block';

  // When the user clicks on <span> (x), close the modal.
  span.onclick = () => {
    modal.style.display = 'none';
  };

  // When the user clicks anywhere outside of the modal, close it.
  window.onclick = (event) => {
    if (event.target === modal) {
      modal.style.display = 'none';
    }
  };
}

function onBodyLoaded() {
  onHashChange();
}

function onHashChange() {
  let configDiv = document.querySelector(location.hash.concat('_container'));
  if (configDiv != null) {
    let containers = document.querySelectorAll('.config-container');
    for (let i = 0; i < containers.length; ++i) {
      containers[i].style.display = 'none';
    }
    configDiv.style.display = '';
  }
}

window.addEventListener('hashchange', onHashChange, false);
