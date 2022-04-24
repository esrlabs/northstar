use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{quote, quote_spanned, ToTokens};

#[proc_macro_attribute]
pub fn runtime_test(_args: TokenStream, mut item: TokenStream) -> TokenStream {
    // If any of the steps for this macro fail, we still want to expand to an item that is as close
    // to the expected output as possible. This helps out IDEs such that completions and other
    // related features keep working.
    let mut input: syn::ItemFn = match syn::parse(item.clone()) {
        Ok(it) => it,
        Err(e) => {
            item.extend(TokenStream::from(e.into_compile_error()));
            return item;
        }
    };

    input.sig.asyncness = None;

    // If type mismatch occurs, the current rustc points to the last statement.
    let (_, last_stmt_end_span) = {
        let mut last_stmt = input
            .block
            .stmts
            .last()
            .map(ToTokens::into_token_stream)
            .unwrap_or_default()
            .into_iter();
        // `Span` on stable Rust has a limitation that only points to the first
        // token, not the whole tokens. We can work around this limitation by
        // using the first/last span of the tokens like
        // `syn::Error::new_spanned` does.
        let start = last_stmt.next().map_or_else(Span::call_site, |t| t.span());
        let end = last_stmt.last().map_or(start, |t| t.span());
        (start, end)
    };

    let body = &input.block;
    let test = quote! {
        /// Initialize the Northstar test environment
        northstar_tests::logger::init();
        log::set_max_level(log::LevelFilter::Debug);

        // Install a custom panic hook that aborts the process in case of a panic *anywhere*
        let default_panic = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            default_panic(info);
            exit(1);
        }));

        // Create a new network namespace
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).expect("failed to craete network namespace");
        // Up the loopback interface
        std::process::Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .spawn()
            .and_then(|mut c| c.wait())
            .expect("failed to up the loopback interface");

        // Enter a new mount namespace in order to alter the mount propagation type on root.
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS).unwrap();
        // Setting the propagation type to MS_PRIVATE ensures that no mounts are left behind
        // upon an abnormal test exit.
        let flags = nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC;
        nix::mount::mount(Some("/"), "/", Option::<&str>::None, flags, Option::<&'static [u8]>::None).expect("failed to remount");

        // Initialize the runtime. The part without the Tokio runtime.
        let runtime = northstar_tests::runtime::Runtime::new().expect("failed to start runtime");

        // The test code within the async context
        let body = async {
            let runtime = runtime.start().await?;
            let r: anyhow::Result<()> = #body;
            runtime.shutdown().await?;
            r
        };

        // Run the test body inside of the Tokio runtime
        #[allow(clippy::expect_used)]
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("failed building the Runtime")
            .block_on(body)

    };

    let brace_token = input.block.brace_token;
    input.block = syn::parse2(quote_spanned! {last_stmt_end_span=>
        {
            use std::os::unix::io::{IntoRawFd, AsRawFd};
            use std::io::{BufRead, Seek};
            use nix::sys::wait::{waitpid, WaitStatus};
            use nix::unistd::{ForkResult, dup2};
            use std::process::exit;

            // Create a memfd for capturing stdout/stderr of the child (test) process
            let mfd = memfd::MemfdOptions::default().create("io").unwrap();

            match unsafe { nix::unistd::fork().expect("fork failed") } {
                ForkResult::Parent { child, .. } => {
                    let result = waitpid(child, None).unwrap();

                    // Copy stdout/stderr from the test to the parents stdout.
                    let mut output = mfd.into_file();
                    output.seek(std::io::SeekFrom::Start(0)).unwrap();
                    // This needs do be done linewise, because a std::io::copy
                    // to std::io::stdout results in conditionless printed output.
                    std::io::BufReader::new(output).lines().for_each(|line| println!("{}", line.unwrap()));

                    // Return depending on the child exit code.
                    match result {
                        WaitStatus::Exited(_, code) if code == 0 => Ok(()),
                        s => Err(anyhow::anyhow!("test failed with status: {:?}", s)),
                    }
                }
                ForkResult::Child => {
                    // Replace stout and stderr with the memfd.
                    dup2(mfd.as_raw_fd(), 1).unwrap();
                    dup2(mfd.into_raw_fd(), 2).unwrap();

                    // Run the test body and exit depending on the result.
                    match { #test } {
                        Ok(_) => exit(0),
                        Err(e) => {
                            eprintln!("{}", e);
                            exit(1);
                        }
                    }
                }
            }
        }
    })
    .expect("Parsing failure");
    input.block.brace_token = brace_token;

    let result = quote! {
        #[::core::prelude::v1::test]
        #input
    };

    result.into()
}
