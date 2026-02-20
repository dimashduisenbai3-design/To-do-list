document.addEventListener("DOMContentLoaded", loadTasks);

function addTask() {
    const input = document.getElementById("taskInput");
    const taskText = input.value.trim();

    if (taskText === "") return;

    const task = {
        text: taskText,
        completed: false
    };

    saveTask(task);
    renderTask(task);
    input.value = "";
}

function renderTask(task) {
    const list = document.getElementById("taskList");
    const li = document.createElement("li");

    li.textContent = task.text;

    if (task.completed) {
        li.classList.add("completed");
    }

    li.onclick = function () {
        li.classList.toggle("completed");
        updateStorage();
    };

    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = "X";
    deleteBtn.onclick = function (e) {
        e.stopPropagation();
        li.remove();
        updateStorage();
    };

    li.appendChild(deleteBtn);
    list.appendChild(li);
}

function saveTask(task) {
    let tasks = JSON.parse(localStorage.getItem("tasks")) || [];
    tasks.push(task);
    localStorage.setItem("tasks", JSON.stringify(tasks));
}

function loadTasks() {
    let tasks = JSON.parse(localStorage.getItem("tasks")) || [];
    tasks.forEach(task => renderTask(task));
}

function updateStorage() {
    const listItems = document.querySelectorAll("#taskList li");
    let tasks = [];

    listItems.forEach(li => {
        tasks.push({
            text: li.firstChild.textContent,
            completed: li.classList.contains("completed")
        });
    });

    localStorage.setItem("tasks", JSON.stringify(tasks));
}
