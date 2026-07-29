use leanbun_approval_macos::observe_current_process_terminal_v1;

fn main() {
    let observation = observe_current_process_terminal_v1();
    println!("{observation:#?}");
}
